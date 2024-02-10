Pod::Spec.new do |spec|
    spec.name                     = 'KmpCrypto'
    spec.version                  = '0.1.5'
    spec.homepage                 = 'https://github.com/skolson/KmpCrypto'
    spec.source                   = { :http=> ''}
    spec.authors                  = 'Steven Olson'
    spec.license                  = 'Apache 2.0'
    spec.summary                  = 'Kotlin Multiplatform Cryptography'
    spec.vendored_frameworks      = 'build/cocoapods/framework/KmpCrypto.framework'
    spec.libraries                = 'c++'
    spec.ios.deployment_target = '14'
                
                
    if !Dir.exist?('build/cocoapods/framework/KmpCrypto.framework') || Dir.empty?('build/cocoapods/framework/KmpCrypto.framework')
        raise "

        Kotlin framework 'KmpCrypto' doesn't exist yet, so a proper Xcode project can't be generated.
        'pod install' should be executed after running ':generateDummyFramework' Gradle task:

            ./gradlew :KmpCrypto:generateDummyFramework

        Alternatively, proper pod installation is performed during Gradle sync in the IDE (if Podfile location is set)"
    end
                
    spec.pod_target_xcconfig = {
        'KOTLIN_PROJECT_PATH' => ':KmpCrypto',
        'PRODUCT_MODULE_NAME' => 'KmpCrypto',
    }
                
    spec.script_phases = [
        {
            :name => 'Build KmpCrypto',
            :execution_position => :before_compile,
            :shell_path => '/bin/sh',
            :script => <<-SCRIPT
                if [ "YES" = "$OVERRIDE_KOTLIN_BUILD_IDE_SUPPORTED" ]; then
                  echo "Skipping Gradle build task invocation due to OVERRIDE_KOTLIN_BUILD_IDE_SUPPORTED environment variable set to \"YES\""
                  exit 0
                fi
                set -ev
                REPO_ROOT="$PODS_TARGET_SRCROOT"
                "$REPO_ROOT/../gradlew" -p "$REPO_ROOT" $KOTLIN_PROJECT_PATH:syncFramework \
                    -Pkotlin.native.cocoapods.platform=$PLATFORM_NAME \
                    -Pkotlin.native.cocoapods.archs="$ARCHS" \
                    -Pkotlin.native.cocoapods.configuration="$CONFIGURATION"
            SCRIPT
        }
    ]
                
end