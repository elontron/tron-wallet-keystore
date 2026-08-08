#
# Be sure to run `pod lib lint TronWalletKeystore.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'TronWalletKeystore'
  s.version          = '1.0.5'
  s.summary          = 'A general-purpose Tron keystore for managing wallets.'

  s.homepage         = 'https://github.com/TronLink/TronWalletKeystore'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = 'tronlinkdev'
  s.source           = { :git => 'https://github.com/TronLink/TronWalletKeystore.git', :tag => s.version.to_s }
  s.platform = :ios, '13.0'
  s.swift_version = '4.2'
  
  s.module_name = 'TronKeystore'
  s.source_files = 'TronWalletKeystore/Classes/**/*'
  s.dependency 'CryptoSwift', '~> 1.8.4'
  s.dependency 'TronWalletABI', '~> 1.0.0'

  s.pod_target_xcconfig = { 'SWIFT_OPTIMIZATION_LEVEL' => '-Owholemodule' }
end
