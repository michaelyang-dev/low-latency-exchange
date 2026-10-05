# lle-admin: operator client for the authenticated admin port (05 §10 E-15).
lle_app(lle_admin_cli SOURCES main.cpp DEPS lle_admin)
set_target_properties(lle_admin_cli PROPERTIES OUTPUT_NAME lle-admin)
