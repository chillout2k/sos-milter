node {
  def app

  stage('Clone repository') {
      sh '/usr/bin/env'
      /* Let's make sure we have the repository cloned to our workspace */
      checkout scm
  }

  stage('Build image') {
      sh '/usr/bin/env'
      /* This builds the actual image; synonymous to
       * docker build on the command line */
      app = docker.build("jenkins/sos-milter")
  }

  stage('Test image') {
      /* Ideally, we would run a test framework against our image.
       * For this example, we're using a Volkswagen-type approach ;-) */
      app.inside {
          sh 'echo "Tests passed"'
      }
  }
  
  stage('Push image') {
    docker.withRegistry('https://dockreg-fra.zwackl.de') {
      app.push()
    }
  }
}
