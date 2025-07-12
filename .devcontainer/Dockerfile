FROM mcr.microsoft.com/devcontainers/ruby:1-3.4-bullseye

RUN mkdir -p /buildtmp \
    && chown -R vscode:vscode /buildtmp

USER vscode
# Set the working directory in the container
WORKDIR /buildtmp
# --- The Caching Strategy ---

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

# 3. Copy the rest of your application code.
# Since your source code changes frequently, we do this last.
# Changes here won't invalidate the 'bundle install' layer above.
# COPY .. .
