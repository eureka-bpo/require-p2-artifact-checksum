def buildLog = new File( basedir, 'build.log' )
assert buildLog.text.contains('For 2 artifacts checksums are not equal:')
