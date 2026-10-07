FROM dinotools/dionaea:latest
RUN sed -i 's#file://var/lib/dionaea/dionaea.json#file:///opt/dionaea/var/log/dionaea/dionaea.json#' /opt/dionaea/template/etc/dionaea/ihandlers-available/log_json.yaml \
 && ln -s ../ihandlers-available/log_json.yaml /opt/dionaea/template/etc/dionaea/ihandlers-enabled/log_json.yaml \
 && mkdir -p /opt/dionaea/var/log/dionaea \
 && chmod 777 /opt/dionaea/var/log/dionaea
