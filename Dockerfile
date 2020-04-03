# a HeapMe lab environment ready for battle
FROM ubuntu:19.10

# Install dependencies
RUN apt-get update -y
RUN apt-get install -y python2.7 python-pip python-setuptools python-dev build-essential python3 python3-pip gdb git cmake gcc g++ pkg-config libglib2.0-dev locales tmux -y
RUN locale-gen en_US.UTF-8
RUN python2 -m pip install pylint python-socketio requests pwntools

# Install htejeda's GEF fork
RUN git clone --depth=1 --quiet https://github.com/htejeda/gef /opt/gef
WORKDIR /opt/gef
RUN python3 -m pip install -r requirements.txt
RUN python3 -m pip install requests pwntools aiohttp python-socketio
RUN git clone --depth=1 --quiet https://github.com/keystone-engine/keystone.git /opt/keystone
WORKDIR /opt/keystone
RUN mkdir build && cd build && sed -i "s/make -j8/make -j$(grep -c processor /proc/cpuinfo)/" ../make-share.sh && ../make-share.sh && make install && cp llvm/lib/libkeystone.so /usr/local/lib
WORKDIR /opt/keystone/bindings/python 
RUN make install install3

# Set Locale to UTF-8 to avoid ASCII enconding complains
RUN echo 'export -p LC_CTYPE=C.UTF-8' >> /root/.profile
ENV LC_CTYPE C.UTF-8

# Heapme ready GDB
WORKDIR /root
RUN echo 'source /opt/gef/gef.py' > .gdbinit
RUN echo 'source /opt/gef/scripts/heapme.py' >> .gdbinit
CMD /usr/bin/gdb
