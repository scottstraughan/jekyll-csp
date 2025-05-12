require 'jekyll'
require_relative 'csp.rb'

module Jekyll  
  class Document
    include CSP

    ##
    # Write document contents
    def write(dest)
      super dest
      trigger_hooks(:post_write)
    end
  end

  class Page
    include CSP

    ##
    # Write page contents
    def write(dest)
      super dest

      Jekyll::Hooks.trigger hook_owner, :post_write, self
    end
  end
end
