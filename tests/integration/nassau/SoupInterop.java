// nassau's SoupBinTCP client against exchanged's order gateway (plan 03 §5, T09).
//
//   java -cp <nassau classpath>:<classes> SoupInterop HOST PORT USER PASSWORD ORDERS EXPECT IDLE_MS OUT DEADLINE_MS
//
// 1. Logs in asking for sequence 1. Sends every OUCH message in ORDERS (one hex line
//    each), as unsequenced data, and waits for EXPECT sequenced messages.
// 2. Stays idle for IDLE_MS while still logged in. nassau ends the session if no
//    server heartbeat arrives within 15 s, so an IDLE_MS above that shows that our
//    heartbeats keep nassau's session alive.
// 3. Logs out, logs in again asking for sequence 1, and checks that the replay of the
//    first EXPECT messages is byte-identical.
// 4. Receives until End of Session and writes the whole stream of the second login
//    to OUT as [u16 big-endian length][message] records.
// Prints one line per step. Exit status: 0 ok, 1 a check failed, 2 usage, 3 heartbeat
// timeout, 4 deadline.
import com.paritytrading.nassau.MessageListener;
import com.paritytrading.nassau.soupbintcp.SoupBinTCP;
import com.paritytrading.nassau.soupbintcp.SoupBinTCPClient;
import com.paritytrading.nassau.soupbintcp.SoupBinTCPClientStatusListener;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

public final class SoupInterop {
  static final class Conn implements MessageListener, SoupBinTCPClientStatusListener {
    final List<byte[]> received = new ArrayList<>();
    boolean accepted, rejected, ended, heartbeatTimeout;
    String session = "";
    long firstSeq;
    SoupBinTCPClient client;

    @Override public void message(ByteBuffer b) {
      byte[] m = new byte[b.remaining()];
      b.get(m);
      received.add(m);
    }
    @Override public void heartbeatTimeout(SoupBinTCPClient c) { heartbeatTimeout = true; }
    @Override public void loginAccepted(SoupBinTCPClient c, SoupBinTCP.LoginAccepted a) {
      accepted = true;
      session = a.getSession().trim();
      firstSeq = a.getSequenceNumber();
    }
    @Override public void loginRejected(SoupBinTCPClient c, SoupBinTCP.LoginRejected r) { rejected = true; }
    @Override public void endOfSession(SoupBinTCPClient c) { ended = true; }
  }

  static long deadline;

  static Conn connect(String host, int port, String user, String password) throws IOException {
    SocketChannel ch = SocketChannel.open(new InetSocketAddress(host, port));
    ch.configureBlocking(false);
    Conn c = new Conn();
    c.client = new SoupBinTCPClient(ch, c, c);
    SoupBinTCP.LoginRequest req = new SoupBinTCP.LoginRequest();
    req.setUsername(user);
    req.setPassword(password);
    req.setRequestedSession("");
    req.setRequestedSequenceNumber(1);
    c.client.login(req);
    while (!c.accepted && !c.rejected) step(c);
    if (c.rejected) {
      System.out.println("login-rejected");
      System.exit(1);
    }
    System.out.println("login-accepted session='" + c.session + "' seq=" + c.firstSeq);
    return c;
  }

  // One round of I/O: read what is there, send a heartbeat if one is due.
  static void step(Conn c) throws IOException {
    if (System.currentTimeMillis() > deadline) {
      System.out.println("deadline");
      System.exit(4);
    }
    int n = c.client.receive();
    c.client.keepAlive();
    if (c.heartbeatTimeout) {
      System.out.println("heartbeat-timeout");
      System.exit(3);
    }
    if (n <= 0) {
      try { Thread.sleep(1); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 9) {
      System.err.println("usage: SoupInterop HOST PORT USER PASSWORD ORDERS EXPECT IDLE_MS OUT DEADLINE_MS");
      System.exit(2);
    }
    final String host = args[0], user = args[2], password = args[3];
    final int port = Integer.parseInt(args[1]);
    final int expect = Integer.parseInt(args[5]);
    final long idleMs = Long.parseLong(args[6]);
    deadline = System.currentTimeMillis() + Long.parseLong(args[8]);
    final HexFormat hex = HexFormat.of();

    Conn first = connect(host, port, user, password);
    int sent = 0;
    for (String line : Files.readAllLines(Path.of(args[4]))) {
      if (line.isBlank()) continue;
      first.client.send(ByteBuffer.wrap(hex.parseHex(line.trim())));
      ++sent;
    }
    System.out.println("sent " + sent);
    while (first.received.size() < expect) step(first);
    System.out.println("received " + first.received.size());

    final long idleEnd = System.currentTimeMillis() + idleMs;
    while (System.currentTimeMillis() < idleEnd) step(first);
    System.out.println("idle-ok ms=" + idleMs + " received " + first.received.size());

    first.client.logout();
    first.client.close();
    System.out.println("logout");

    Conn second = connect(host, port, user, password);
    while (second.received.size() < first.received.size()) step(second);
    for (int i = 0; i < first.received.size(); ++i) {
      if (!Arrays.equals(first.received.get(i), second.received.get(i))) {
        System.out.println("replay-differs at " + (i + 1));
        System.exit(1);
      }
    }
    System.out.println("replay-identical n=" + first.received.size());

    while (!second.ended) step(second);
    System.out.println("eos received " + second.received.size());
    try (DataOutputStream out = new DataOutputStream(new FileOutputStream(args[7]))) {
      for (byte[] m : second.received) {
        out.writeShort(m.length);
        out.write(m);
      }
    }
    second.client.close();
    System.out.println("done");
    System.exit(0);
  }
}
