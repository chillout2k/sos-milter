node {
  def app

  stage('Clone repository') {
      sh '/usr/bin/env'
      checkout scm
  }

  stage('Build image') {
    sh '/usr/bin/env'
    /* Multi-Branch Pipeline works with env.BRANCH_NAME*/
    app = docker.build("sos-milter:${env.BRANCH_NAME}","--pull --label BUILD_URL=${env.BUILD_URL} .")
  }

  stage('Test image') {
    app.inside {
      sh '/usr/bin/env'
      sh '/bin/ps auxwwf'
    }
  }

  stage('Push image') {
    app.push()
  }

  stage('Cleanup') {
    sh 'echo "TODO: cleanup!"'
  }
}
