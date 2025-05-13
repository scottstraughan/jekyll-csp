require 'jekyll'
require 'nokogiri'
require 'digest'
require 'open-uri'
require 'uri'

##
# Provides the ability to generate a content security policy for inline scripts and styles.
# Will reuse an existing CSP or generate a new one and insert in HEAD.
module CSP
  ##
  # Provides the ability to generate a content security policy for inline scripts and styles.
  # Will reuse an existing CSP or generate a new one and insert in HEAD.
  class Generator
    def initialize(document_html)
      @document_html = document_html
      @nokogiri = Nokogiri::HTML(document_html)

      @csp_tags = {
        "frame-src" => [],
        "script-src" => [],
        "img-src" => [],
        "style-src" => []
      }

      config = Jekyll.configuration({})['jekyll_csp']
      
      @indentation = config['indentation'] || 2
      @enable_newlines = config['newlines'].to_s ? config['newlines'] : true
      @debug = config['debug'].to_s ? config['debug'] : false
      @inject_self = config['inject_self'] || ['script-src', 'style-src', 'img-src', 'frame-src']

      if @enable_newlines == false
        @indentation = 0
      end

      self.write_debug_log(config)
    end

    ##
    # Write a debug log
    def write_debug_log(content)
      if @debug
        Jekyll.logger.warn content
      end
    end

    ##
    # Generate a CSP entry using the correct indentation and formatting
    def generate_meta_entry(tag, items)
      # Remove duplicates
      items = items.uniq

      # Line separator
      line_sep = @enable_newlines ? "\n" : ""

      if items.empty?
        return "" << line_sep  << self.get_indent_str(3) << tag << ';'
      end

      "" \
      << line_sep  \
      << self.get_indent_str(3) \
      << tag \
      << " " \
      << line_sep \
      << self.get_indent_str(4) \
      << items.join(" " + line_sep + self.get_indent_str(4)) \
      << "; "
    end

    ##
    # Get an indentation string.
    def get_indent_str(count)
      " " * (@indentation * count)
    end

    ##
    # Creates an HTML content security policy meta tag.
    def generate_convert_security_policy_meta_tag
      meta_content = ""

      @csp_tags.each do |tag, items|
        meta_content += self.generate_meta_entry(tag, items)
      end

      csp = self.get_or_create_csp_tag
      csp['content'] = meta_content
    end

    ## Locate an existing CSP or create one
    def get_or_create_csp_tag
      csp = @nokogiri.at_xpath("//meta[translate(@http-equiv, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') = 'content-security-policy']")

      if csp
        return csp
      end

      tag = "<meta http-equiv=\"Content-Security-Policy\" content="">"

      if @nokogiri.at("head")
        self.write_debug_log("Generated content security policy, inserted in HEAD.")
        @nokogiri.at("head") << tag
      elsif @nokogiri.at("body")
        self.write_debug_log("Generated content security policy, inserted in BODY.")
        @nokogiri.at("body") << tag
      else
        self.write_debug_log("Generated content security policy but found no-where to insert it.")
      end

      csp = @nokogiri.at_xpath("//meta[translate(@http-equiv, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') = 'content-security-policy']")
      return csp
    end

    ##
    # Parse an existing content security policy meta tag
    def parse_existing_meta_element()
      csp = self.get_or_create_csp_tag

      if csp
        content = csp.attr('content')
        content = content.strip! || content
        policies = content.split(';')
        
        policies.each do |policy|
          policy = policy.strip
          
           policy_tag = policy
           policy_items = []

          if policy.include? ' '
            policy_parts = policy.split(' ')
            policy_tag = policy_parts[0]
            policy_items = policy_parts.drop(1)
          end

          # If an existing tag doesn't exist, add it
          if !@csp_tags.key?(policy_tag)
            @csp_tags[policy_tag] = []
          end
          
          # Concat the tag items
          @csp_tags[policy_tag].concat(policy_items)
        end

        @nokogiri.search('meta[http-equiv="Content-Security-Policy"]').each do |el|
          el.remove
        end
      end
    end

    ##
    # Initialize some default values
    def inject_defaults
      @csp_tags.each do |directive, properties|
        if @inject_self.include? directive
          properties.push("'self'")
        end
      end
    end

    ##
    # This function converts elements with style="color:red" attributes into inline styles
    def convert_all_inline_styles_attributes
      @nokogiri.css('*').each do |find|
        find_src = find.attr('style')

        if find_src
          if find.attr('id')
            element_id = find.attr('id')
          else
            hash = Digest::MD5.hexdigest find_src + "#{Random.rand(11)}"
            element_id = "csp-gen-" + hash
            find["id"] = element_id
          end

          new_element = "<style>#" + element_id + " { " + find_src + " } </style>"
          find.remove_attribute("style")

          if @nokogiri.at('head')
            @nokogiri.at('head') << new_element
            self.write_debug_log('Converting style attribute to inline style, inserted into HEAD.')
          else
            if @nokogiri.at('body')
              @nokogiri.at('body') << new_element
              Jekyll.logger.info
              self.write_debug_log('Converting style attribute to inline style, inserted into BODY.')
            else
              self.write_debug_log('Unable to convert style attribute to inline style, no HEAD or BODY found.')
            end
          end
        end
      end
    end

    ##
    # Find all images
    def find_images
      @nokogiri.css('img').each do |find|
        find_src = find.attr('src')

        if find_src and find_src.start_with?('http', 'https')
          @csp_tags['img-src'].push find_src.match(/(.*\/)+(.*$)/)[1]
        end
      end

      @nokogiri.css('style').each do |find|
        finds = find.content.scan(/url\(([^\)]+)\)/)

        finds.each do |innerFind|
          innerFind = innerFind[0]
          innerFind = innerFind.tr('\'"', '')
          if innerFind.start_with?('http', 'https')
            @csp_tags['img-src'].push self.get_domain(innerFind)
          end
        end
      end

    end

    ##
    # Find all scripts
    def find_scripts
      @nokogiri.css('script').each do |find|
        if find.attr('src')
          find_src = find.attr('src')

          if find_src and find_src.start_with?('http', 'https')
            @csp_tags['script-src'].push find_src.match(/(.*\/)+(.*$)/)[1]
          end

        else
          @csp_tags['script-src'].push self.generate_sha256_content_hash find.content
        end
      end
    end

    ##
    # Find all inline stylesheets
    def find_inline_styles
      @nokogiri.css('style').each do |find|
        @csp_tags['style-src'].push self.generate_sha256_content_hash find.content
      end
    end

    ##
    # Find all linked stylesheets
    def find_linked_styles
      @nokogiri.css('link').each do |find|
        self.write_debug_log(find)
        find_attr = find.attr('href')

        if find_attr
            @csp_tags['style-src'].push find_attr
        else
          self.write_debug_log("Found linked style with no href." << find)
        end
      end
    end

    ##
    # Find all iframes
    def find_frames
      @nokogiri.css('iframe, frame').each do |find|
        find_src = find.attr('src')

        if find_src and find_src.start_with?('http', 'https')
          @csp_tags['frame-src'].push find_src
        end
      end
    end

    def get_domain(url)
      uri = URI.parse(url)
      "#{uri.scheme}://#{uri.host}"
    end

    ##
    # Generate a SHA256 hash from content
    def generate_sha256_content_hash(content)
      hash = Digest::SHA2.base64digest content
      "'sha256-#{hash}'"
    end

    ##
    # Builds an HTML meta tag based on the found inline scripts and style hashes
    def run
      self.parse_existing_meta_element
      self.inject_defaults
      self.convert_all_inline_styles_attributes

      # Find elements in document
      self.find_linked_styles
      self.find_images
      self.find_inline_styles
      self.find_scripts
      self.find_frames

      self.generate_convert_security_policy_meta_tag

      @nokogiri.to_html
    end
  end

  ##
  # Write the file contents back.
  def write_file_contents(dest, content)
    FileUtils.mkdir_p(File.dirname(dest))
    File.open(dest, 'w') do |f|
      f.write(content)
    end
  end

  ##
  # Write document contents
  def write(dest)
    dest_path = destination(dest)

    if File.extname(dest_path) == ".html"
      content_security_policy_generator = Generator.new output
      self.write_file_contents(dest_path, content_security_policy_generator.run)
    else
      self.write_file_contents(dest_path, output)
    end

  end
end