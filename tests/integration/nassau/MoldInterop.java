// nassau's MoldUDP64 client against exchanged's market-data publisher and re-request
// server, through a lossy relay (plan 03 §5, T08).
//
//   java -cp <nassau classpath>:<classes> MoldInterop RELAY_PORT CLIENT_PORT RR_HOST RR_PORT LOSS_PERMILLE SEED OUT DEADLINE_MS
//
// exchanged publishes line A to 127.0.0.1:RELAY_PORT. The relay forwards each datagram
// to nassau's client at 127.0.0.1:CLIENT_PORT, but drops a seeded LOSS_PERMILLE of
// them. nassau detects the gaps and re-requests them from RR_HOST:RR_PORT; the
// re-request path itself is lossless. After End of Session, and once every message
// up to it has been delivered, the program writes the stream to OUT as
// [u16 big-endian length][message] records.
// Prints a summary line. Exit status: 0 ok, 1 a check failed, 2 usage, 4 deadline.
import com.paritytrading.nassau.MessageListener;
import com.paritytrading.nassau.moldudp64.MoldUDP64Client;
import com.paritytrading.nassau.moldudp64.MoldUDP64ClientState;
import com.paritytrading.nassau.moldudp64.MoldUDP64ClientStatusListener;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.SplittableRandom;

public final class MoldInterop {
  static final List<byte[]> delivered = new ArrayList<>();
  static long requests, requestedMessages, gapFills, eosSeq = -1;
  static boolean ended;

  public static void main(String[] args) throws Exception {
    if (args.length != 8) {
      System.err.println("usage: MoldInterop RELAY_PORT CLIENT_PORT RR_HOST RR_PORT LOSS_PERMILLE SEED OUT DEADLINE_MS");
      System.exit(2);
    }
    final int relayPort = Integer.parseInt(args[0]), clientPort = Integer.parseInt(args[1]);
    final InetSocketAddress rr = new InetSocketAddress(args[2], Integer.parseInt(args[3]));
    final int loss = Integer.parseInt(args[4]);
    final SplittableRandom rng = new SplittableRandom(Long.parseLong(args[5]));
    final long deadline = System.currentTimeMillis() + Long.parseLong(args[7]);

    DatagramChannel relay = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", relayPort));
    relay.configureBlocking(false);
    DatagramChannel channel = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", clientPort));
    channel.configureBlocking(false);
    DatagramChannel requestChannel = DatagramChannel.open().bind(new InetSocketAddress("127.0.0.1", 0));
    requestChannel.configureBlocking(false);
    final InetSocketAddress clientAddr = new InetSocketAddress("127.0.0.1", clientPort);

    MessageListener listener = b -> {
      byte[] m = new byte[b.remaining()];
      b.get(m);
      delivered.add(m);
    };
    MoldUDP64ClientStatusListener status = new MoldUDP64ClientStatusListener() {
      @Override public void state(MoldUDP64Client c, MoldUDP64ClientState s) {
        if (s == MoldUDP64ClientState.GAP_FILL) ++gapFills;
      }
      @Override public void downstream(MoldUDP64Client c, long seq, int count) {}
      @Override public void request(MoldUDP64Client c, long seq, int count) {
        ++requests;
        requestedMessages += count;
      }
      @Override public void endOfSession(MoldUDP64Client c) { ended = true; }
    };
    MoldUDP64Client client = new MoldUDP64Client(channel, requestChannel, rr, listener, status);
    System.out.println("ready relay=" + relayPort + " client=" + clientPort);

    ByteBuffer buf = ByteBuffer.allocate(65536);
    long relayed = 0, dropped = 0;
    long quietSince = System.currentTimeMillis();
    while (true) {
      if (System.currentTimeMillis() > deadline) {
        System.out.println("deadline delivered=" + delivered.size() + " requests=" + requests);
        System.exit(4);
      }
      boolean did = false;
      buf.clear();
      if (relay.receive(buf) != null) {
        buf.flip();
        did = true;
        // The End of Session sequence number: the packet's sequence number when its
        // message count is 0xFFFF (MoldUDP64 1.00).
        if (buf.remaining() >= 20 && (buf.getShort(18) & 0xFFFF) == 0xFFFF) eosSeq = buf.getLong(10);
        if (rng.nextInt(1000) < loss) {
          ++dropped;
        } else {
          channel.send(buf, clientAddr);
          ++relayed;
        }
      }
      if (client.receive()) did = true;
      if (client.receiveResponse()) did = true;
      if (did) quietSince = System.currentTimeMillis();
      if (ended && eosSeq > 0 && delivered.size() >= eosSeq - 1) break;
      // After End of Session and 3 s without traffic, nothing more can arrive.
      if (ended && System.currentTimeMillis() - quietSince > 3000) break;
      if (!did) Thread.sleep(1);
    }
    try (DataOutputStream out = new DataOutputStream(new FileOutputStream(args[6]))) {
      for (byte[] m : delivered) {
        out.writeShort(m.length);
        out.write(m);
      }
    }
    final boolean complete = eosSeq > 0 && delivered.size() == eosSeq - 1;
    System.out.println("eos delivered=" + delivered.size() + " eos_seq=" + eosSeq + " relayed=" + relayed +
                       " dropped=" + dropped + " requests=" + requests + " requested_messages=" + requestedMessages +
                       " gap_fills=" + gapFills + " complete=" + complete);
    System.exit(complete ? 0 : 1);
  }
}
