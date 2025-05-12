#!/usr/bin/env bash

gem uninstall jekyll-csp

gem build *.gemspec

gem install *.gem

cd test-site

bundle exec jekyll build