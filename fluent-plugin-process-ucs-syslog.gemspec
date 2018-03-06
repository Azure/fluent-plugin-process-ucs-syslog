# encoding: utf-8
$:.push File.expand_path('../lib', __FILE__)


Gem::Specification.new do |gem|
  gem.name        = "fluent-plugin-process-ucs-syslog"
  gem.description = "Filter plugin for appending various field in the record from UCS syslog"
  gem.homepage    = "https://github.com/PakDLiu/fluent-plugin-process-ucs-syslog"
  gem.summary     = gem.description
  gem.version     = File.read("VERSION").strip
  gem.authors     = ["Donald Liu"]
  gem.email       = "neobahamutxzero@gmail.com"
  gem.has_rdoc    = false
  #gem.platform    = Gem::Platform::RUBY
  gem.license     = 'MIT'
  gem.files       = `git ls-files`.split("\n")
  gem.test_files  = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ['lib']

  gem.add_dependency "fluentd", [">= 0.14.0", "< 2"]
  gem.add_development_dependency "rake", ">= 0.9.2"
  gem.add_development_dependency("test-unit", ["~> 3.1.4"])
end