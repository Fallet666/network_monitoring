FROM docker.elastic.co/kibana/kibana:7.15.0

COPY setup_kibana.sh /usr/local/bin/setup_kibana.sh
RUN chmod +x /usr/local/bin/setup_kibana.sh

CMD ["/usr/local/bin/setup_kibana.sh"]