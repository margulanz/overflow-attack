FROM iwaseyusuke/mininet
RUN apt update && apt install -y iperf iproute2
WORKDIR /topo
ENTRYPOINT []
CMD ["bash", "-c", "service openvswitch-switch start && sleep 2 && python3 /topo/topology.py"]
#CMD service openvswitch-switch start && python3 /topo/topology.py

