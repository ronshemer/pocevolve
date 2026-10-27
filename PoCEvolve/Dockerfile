# Use the latest Ubuntu image
FROM patched_node

USER root

# Set the working directory
WORKDIR /app

# Install git and tree
RUN apt-get update && \
    apt-get install -y git tmux python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

RUN touch /flag.txt && chmod 777 /flag.txt
COPY resources/genpoc.c /tmp/genpoc.c
RUN gcc /tmp/genpoc.c -o /usr/bin/genpoc && rm /tmp/genpoc.c && chmod 4555 /usr/bin/genpoc
COPY requirements.txt /tmp/pocevolve-requirements.txt
RUN pip3 install -r /tmp/pocevolve-requirements.txt && rm /tmp/pocevolve-requirements.txt

USER node
