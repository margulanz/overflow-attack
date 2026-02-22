FROM osrg/ryu

# Install build tools for Python 2
RUN apt-get update && apt-get install -y \
    gcc \
    python-dev \
    python-pip \
    build-essential

# Install Python-2-compatible psutil
RUN pip install "psutil<6"
WORKDIR /root
# Copy the entire apps folder as a module
COPY apps /root/apps

# Add apps to Python path
ENV PYTHONPATH=/root:$PYTHONPATH


#CMD ["ryu-manager", "ryu.app.simple_switch_13"]
#CMD ["ryu-manager", "apps.controller", "ryu.app.ofctl_rest"]


# MODE can be fixed or adaptive
ENV MODE=adaptive

ENV FIXED_TIMEOUT=10
CMD ["ryu-manager", "apps.vita-controller"]
