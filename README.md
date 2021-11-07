# Projeto-SRSC---Movie-Streaming
Movie Streaming Project for the Computer and Networks Security Course from the Masters in Computer Sciences from SST NOVA.

This project consists of the implementation of a simple system model, emulating how certain services are commonly provided in this day and age, with a more concerned focus on the
security aspect of those same services.

The system model consists of a private proxy server, that communicates with two other servers: a Streaming server and a Signaling server. The first holds a static storage of movie
files(.dat) and can transmit them to its clients through encrypted frames; the second holds all the user certificates and necessary security information for the well-functioning of
the system, as a whole.

The proxy and the Signaling server communicate through the SAPKDP protocol, while the proxy and the Streaming server communicate through the RTSP protocol. These communications are
theoretically exposed to adversarial conditions, such as IP spoofing or masquerading, authenticity breaks, integritry breaks and confidentiality breaks, hence the security 
requirements for this project.

The implementation of the model will be done modularly, with the first phase consisting of:

-> Development of the ProxyBox and StreamingServer, extending the provided implementations(hjUDPproxy.java and hjStreamServer.java, respectfully);

-> Can start by using “static” configurations. Configuration files manually installed in ProxyBOX and Streaming Server;

-> The SRTSP for the streaming phase only requires Symmetric Crypto and MACs, but the cryptography in use must be configurable.

(Later on, the static configurations must be removed after the complete implementation of the SRTSP and SAPKDP protocols, as well as the Signaling Server.)
