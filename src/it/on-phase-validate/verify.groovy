def buildLog = new File( basedir, 'build.log' )
assert buildLog.text.contains('Checksums analysis has been correctly finished: 3 artifacts have correct checksums, 0 artifacts have no checksum information')
