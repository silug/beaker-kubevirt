FROM mcr.microsoft.com/devcontainers/ruby:1-3.4-bullseye

RUN mkdir -p /buildtmp \
    && chown -R vscode:vscode /buildtmp

# setup the container to preserve bash history across restarts
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
    && mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && chown -R vscode:vscode /commandhistory \
    && echo "$SNIPPET" >> "/home/vscode/.bashrc"

USER vscode
WORKDIR /home/vscode

RUN set -x; cd "$(mktemp -d)" && \
  OS="$(uname | tr '[:upper:]' '[:lower:]')" && \
  ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" && \
  KREW="krew-${OS}_${ARCH}" && \
  curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" && \
  tar zxvf "${KREW}.tar.gz" && \
  ./"${KREW}" install krew

# Add krew to PATH
RUN cat >> /home/vscode/.bashrc <<EOF
# Add krew to PATH
export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"

# Enable shell completion for kubectl
source <(kubectl completion bash)

alias k="kubectl"
complete -o default -F __start_kubectl k

EOF

COPY --chown=vscode:vscode .devcontainer/.pryrc ./
RUN mkdir -p /home/vscode/.ssh && \
    chown -R vscode:vscode /home/vscode/.ssh && \
    chmod 700 /home/vscode/.ssh
# Set the working directory in the container
WORKDIR /buildtmp
RUN bundle config path /home/vscode/.bundle
# 1. Copy only the files that define your dependencies.
# The layer cache for the next step will only be invalidated
# if these specific files change.
COPY --chown=vscode:vscode ../*.gemspec ./
COPY --chown=vscode:vscode ../Gemfile* ./
# Need the version.rb file to allow bundler to run
COPY --chown=vscode:vscode ../lib/beaker/kubevirt/version.rb ./lib/beaker/kubevirt/version.rb

# 2. Install all dependencies using Bundler.
# This is the time-consuming step that we want to cache.
# It will only re-run if the .gemspec or Gemfile changes.
RUN bundle install --jobs "$(nproc)"
