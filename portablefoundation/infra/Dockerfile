#
# Simple docker file hosting a build environment
#
# SSH server listens to SSH port 5000
#
FROM ubuntu:14.04
MAINTAINER	Kannan Varadhan <kvaradha@cisco.com>
# Add the "universe" package repository to get the daemontools
RUN echo "deb http://archive.ubuntu.com/ubuntu trusty main universe" > /etc/apt/sources.list
RUN apt-get -qq update
RUN apt-get -qqy install gcc gdb
RUN apt-get install make
RUN apt-get install -y openssh-server
RUN apt-get install -y daemontools
RUN mkdir -p /etc/service
RUN mkdir -p /etc/service/sshd /var/run/sshd
# Give root user in container a default password.
RUN echo 'root:cisco123' | chpasswd

#Enable Password authentication via ssh into the container.
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config
RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
RUN sed -i 's/Port 22/Port 5000/g' /etc/ssh/sshd_config
# Use daemontools to start sshd
RUN echo "#!/bin/bash\nexec /usr/sbin/sshd -D >/dev/null 2>&1" > /etc/service/sshd/run
RUN chmod +x /etc/service/sshd/run

#
# Run a test
#
#ADD env_test.sh env_test.sh
#RUN chmod +x env_test.sh
#CMD ./env_test.sh

#
# Add a sample REST API client to obtain the UDI
#
RUN mkdir -p /home/snbi
ADD pf-req.py /home/snbi/pf-req.py

RUN mkdir -p /etc/service/pf-reference-client
RUN echo "#!/bin/bash\ncd /home/snbi\nexec /usr/bin/python pf-req.py\nwhile [ 1 ]; do\n   sleep 1000\ndone\n" > /etc/service/pf-reference-client/run
RUN chmod +x /etc/service/pf-reference-client/run

EXPOSE 5000
ENTRYPOINT ["/usr/bin/svscan", "/etc/service/"]
