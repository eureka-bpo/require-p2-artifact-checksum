def buildLog = new File( basedir, 'build.log' )
assert buildLog.text.contains('Error has occured while reading artifacts list from https://download.eclipse.org/releases/2023-09/000000000000/')
