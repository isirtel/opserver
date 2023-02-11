AUTOMAKE_OPTIONS=foreign
bin_PROGRAMS=webserver

webserver_SOURCES= webserver.c \
core/nginx.c \
core/ngx_log.c \
core/ngx_palloc.c \
core/ngx_array.c \
core/ngx_list.c \
core/ngx_hash.c \
core/ngx_buf.c \
core/ngx_queue.c \
core/ngx_output_chain.c \
core/ngx_string.c \
core/ngx_parse.c \
core/ngx_parse_time.c \
core/ngx_inet.c \
core/ngx_file.c \
core/ngx_crc32.c \
core/ngx_murmurhash.c \
core/ngx_md5.c \
core/ngx_sha1.c \
core/ngx_rbtree.c \
core/ngx_radix_tree.c \
core/ngx_slab.c \
core/ngx_times.c \
core/ngx_shmtx.c \
core/ngx_connection.c \
core/ngx_cycle.c \
core/ngx_spinlock.c \
core/ngx_rwlock.c \
core/ngx_cpuinfo.c \
core/ngx_conf_file.c \
core/ngx_module.c \
core/ngx_resolver.c \
core/ngx_open_file_cache.c \
core/ngx_crypt.c \
core/ngx_proxy_protocol.c \
core/ngx_syslog.c \
event/ngx_event.c \
event/ngx_event_timer.c \
event/ngx_event_posted.c \
event/ngx_event_accept.c \
event/ngx_event_udp.c \
event/ngx_event_connect.c \
event/ngx_event_pipe.c \
os/unix/ngx_time.c \
os/unix/ngx_errno.c \
os/unix/ngx_alloc.c \
os/unix/ngx_files.c \
os/unix/ngx_socket.c \
os/unix/ngx_recv.c \
os/unix/ngx_readv_chain.c \
os/unix/ngx_udp_recv.c \
os/unix/ngx_send.c \
os/unix/ngx_writev_chain.c \
os/unix/ngx_udp_send.c \
os/unix/ngx_udp_sendmsg_chain.c \
os/unix/ngx_channel.c \
os/unix/ngx_shmem.c \
os/unix/ngx_process.c \
os/unix/ngx_daemon.c \
os/unix/ngx_setaffinity.c \
os/unix/ngx_setproctitle.c \
os/unix/ngx_posix_init.c \
os/unix/ngx_user.c \
os/unix/ngx_dlopen.c \
os/unix/ngx_process_cycle.c \
os/unix/ngx_linux_init.c \
event/modules/ngx_epoll_module.c \
os/unix/ngx_linux_sendfile_chain.c \
event/ngx_event_openssl.c \
event/ngx_event_openssl_stapling.c \
core/ngx_regex.c \
http/ngx_http.c \
http/ngx_http_core_module.c \
http/ngx_http_special_response.c \
http/ngx_http_request.c \
http/ngx_http_parse.c \
http/modules/ngx_http_log_module.c \
http/ngx_http_request_body.c \
http/ngx_http_variables.c \
http/ngx_http_script.c \
http/ngx_http_upstream.c \
http/ngx_http_upstream_round_robin.c \
http/ngx_http_file_cache.c \
http/ngx_http_write_filter_module.c \
http/ngx_http_header_filter_module.c \
http/modules/ngx_http_chunked_filter_module.c \
http/modules/ngx_http_range_filter_module.c \
http/modules/ngx_http_gzip_filter_module.c \
http/ngx_http_postpone_filter_module.c \
http/modules/ngx_http_ssi_filter_module.c \
http/modules/ngx_http_charset_filter_module.c \
http/modules/ngx_http_userid_filter_module.c \
http/modules/ngx_http_headers_filter_module.c \
http/ngx_http_copy_filter_module.c \
http/modules/ngx_http_not_modified_filter_module.c \
http/modules/ngx_http_static_module.c \
http/modules/ngx_http_autoindex_module.c \
http/modules/ngx_http_index_module.c \
http/modules/ngx_http_mirror_module.c \
http/modules/ngx_http_try_files_module.c \
http/modules/ngx_http_auth_basic_module.c \
http/modules/ngx_http_access_module.c \
http/modules/ngx_http_limit_conn_module.c \
http/modules/ngx_http_limit_req_module.c \
http/modules/ngx_http_geo_module.c \
http/modules/ngx_http_map_module.c \
http/modules/ngx_http_split_clients_module.c \
http/modules/ngx_http_referer_module.c \
http/modules/ngx_http_rewrite_module.c \
http/modules/ngx_http_ssl_module.c \
http/modules/ngx_http_proxy_module.c \
http/modules/ngx_http_fastcgi_module.c \
http/modules/ngx_http_uwsgi_module.c \
http/modules/ngx_http_scgi_module.c \
http/modules/ngx_http_memcached_module.c \
http/modules/ngx_http_empty_gif_module.c \
http/modules/ngx_http_browser_module.c \
http/modules/ngx_http_upstream_hash_module.c \
http/modules/ngx_http_upstream_ip_hash_module.c \
http/modules/ngx_http_upstream_least_conn_module.c \
http/modules/ngx_http_upstream_random_module.c \
http/modules/ngx_http_upstream_keepalive_module.c \
http/modules/ngx_http_upstream_zone_module.c \
ngx_modules.c

webserver_includedir=$(prefix)/include/module
webserver_include_HEADERS=

webserver_CFLAGS  = -I$(top_srcdir)/src
webserver_CFLAGS += -I$(top_srcdir)/src/module/webserver/core
webserver_CFLAGS += -I$(top_srcdir)/src/module/webserver/event
webserver_CFLAGS += -I$(top_srcdir)/src/module/webserver/event/modules
webserver_CFLAGS += -I$(top_srcdir)/src/module/webserver/os/unix
webserver_CFLAGS += -I$(top_srcdir)/src/module/webserver/http
webserver_CFLAGS += -I$(top_srcdir)/src/module/webserver/http/modules
webserver_CFLAGS += -I$(prefix)/include
webserver_CFLAGS += -g -W -Wall -Wchar-subscripts -Wcomment -Wformat -Wimplicit -Wmissing-braces \
	-Wno-error=unused-result -Wparentheses -Wswitch -Wno-unused-parameter  -Wfloat-equal -Wsign-compare -Wpointer-arith -Winline -Werror -Wno-error=deprecated-declarations -Wno-deprecated-declarations  -rdynamic -std=gnu99 
webserver_LDFLAGS = -L$(top_builddir)/src/opbox/.libs
webserver_LDFLAGS += -L$(top_builddir)/src/base/.libs
webserver_LDFLAGS += -L$(prefix)/lib
webserver_LDADD = -lpthread -levent -lbase -liniparser -lopbox -ldl -lcrypt -lpcre -lssl -lcrypto -lz

webserveretcdir = $(prefix)/etc/webserver
webserveretc_DATA=webserver.conf 

webserver1etcdir = $(prefix)/etc/webserver/conf
webserver1etc_DATA=conf/fastcgi.conf conf/fastcgi_params  conf/koi-utf  conf/koi-win  conf/mime.types  conf/scgi_params  conf/uwsgi_params  conf/win-utf conf/server.key conf/server.crt
webserver2etcdir = $(prefix)/log/webserver
webserver2etc_DATA=.log
