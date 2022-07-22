
Pod::Spec.new do |s|
  s.name             = 'ZDeviceHelper'
  s.version          = '1.0.0'
  s.summary          = 'ZDeviceHelper is used for device information'

  s.description      = "This library contains all information related to a device which helps a developer to use it in their project and get device information that is required in their project."

  s.homepage         = 'https://www.zensar.com/'
  s.license          = 'MIT'
  s.author           = { 'shekharvishwazensar' => 'shekhar.vishwakarma@zensar.com' }
  s.source           = {
    :git => 'https://github.com/shekharvishwazensar/ZDeviceHelper',
    :tag => s.version.to_s }

  s.ios.deployment_target = '11.0'
  s.platform     = :ios, '11.0'
  s.requires_arc = true
  s.default_subspec = 'All'
  s.swift_versions = '5.0'

  s.subspec "All" do |sp|
    # Internal dependencies
    
    # Third Party Dependencies

    sp.source_files = 'ZDeviceHelper/**/*.{swift}'
   
  end
end
