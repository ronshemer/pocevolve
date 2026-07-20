# Use the latest Ubuntu image
FROM patched_node

# Set the working directory
WORKDIR /app

# Install git and tree
RUN apt-get update && \
    apt-get install -y git tmux && \
    rm -rf /var/lib/apt/lists/*

RUN touch /flag.txt && chmod 777 /flag.txt
RUN useradd -m -u 1000 -s /bin/bash node
COPY resources/genpoc.c /tmp/genpoc.c
RUN gcc /tmp/genpoc.c -o /usr/bin/genpoc && rm /tmp/genpoc.c && chmod 4555 /usr/bin/genpoc