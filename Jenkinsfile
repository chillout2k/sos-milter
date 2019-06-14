pipeline {
  agent any

  environment {
    dockerImage = ''
  }

  parameters {
    string name: 'dockerRegistry', trim: true
  }

  stages {
    stage('Build image') {
      steps {
        sh '/usr/bin/env'
        script {
          /* Multi-Branch Pipeline works with env.BRANCH_NAME*/
          dockerImage = docker.build("sos-milter:${env.BRANCH_NAME}","--pull --label BUILD_URL=${env.BUILD_URL} .")
        }
      }
    }
    stage('Test image') {
      steps {
        script {
          dockerImage.inside {
            sh '/usr/bin/env'
            sh '/bin/ps auxwwf'
          }
        }
      }
    }
    stage('Push image') {
      steps {
        script {
          docker.withRegistry(env.dockerRegistry) {
            dockerImage.push()
          }
        }
      }
    }
    stage('Cleanup') {
      steps {
        sh 'echo "TODO: cleanup!"'
      }
    }
  }
}

