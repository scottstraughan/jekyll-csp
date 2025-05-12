lib = File.expand_path("../lib", __FILE__)

$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "jekyll-csp/version"

Gem::Specification.new do |spec|
  spec.name          = "jekyll-csp"
  spec.summary       = "Generate a Content Security Policy HTML meta tag based on found inline scripts, inline styles etc."
  spec.description   = "Will generate a content-security-policy based on images, scripts, stylesheets, frames and"\
                       "others on each generated page. This script assumes that all your linked resources as 'safe'."\
                       "Style attributes will also be converted into <style> elements and SHA256 hashes will be"\
                       "generated for inline styles/scripts."
  spec.version       = JekyllCSP::VERSION
  spec.authors       = ["scottstraughan"]
  spec.email         = [""]
  spec.homepage      = "https://github.com/scottstraughan/jekyll-csp"
  spec.licenses      = ["MIT"]
  spec.files         = Dir['lib/**/*.rb'] + Dir['lib/*.rb']
  spec.require_paths = ["lib"]
  spec.add_dependency 'jekyll', '>= 4.4.0'
  spec.add_dependency 'digest', '>= 3.2.0'
  spec.add_dependency 'nokogiri', '>= 1.18.0'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec'
  spec.add_development_dependency 'rubocop'
end
