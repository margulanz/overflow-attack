FROM osrg/ryu

# Install build tools for Python 2
RUN echo 'Acquire::http::Pipeline-Depth "0";' > /etc/apt/apt.conf.d/99fixbadproxy \
 && echo 'Acquire::http::No-Cache "true";' >> /etc/apt/apt.conf.d/99fixbadproxy \
 && echo 'Acquire::BrokenProxy "true";' >> /etc/apt/apt.conf.d/99fixbadproxy
 

RUN apt-get update && apt-get install -y \
    gcc \
    python-dev \
    python-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY KazDreamCyberGuard.crt /usr/local/share/ca-certificates/
RUN apt-get update && apt-get install -y ca-certificates \
 && update-ca-certificates
# Install Python-2-compatible psutil
RUN pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org  "psutil<6"
WORKDIR /root
# Copy the entire apps folder as a module
COPY apps /root/apps

# Add apps to Python path
ENV PYTHONPATH=/root:$PYTHONPATH

#CMD ["ryu-manager", "--observe-links" ,"apps.git_multipath"]
#CMD ["ryu-manager", "--observe-links","apps.multipath"]
#CMD ["ryu-manager", "ryu.app.simple_switch_13"]
CMD ["ryu-manager", "apps.controller", "ryu.app.ofctl_rest"]
