pipeline {
  agent any

  parameters {
    string name: 'dockerRegistry', trim: true
  }

  environment {
    dockerImage = ''
    imageName = 'sos-milter'
  }

  stages {
    stage('Build image') {
      steps {
        sh '/usr/bin/env'
        script {
          dockerImage = docker.build(
            "${env.imageName}:${env.BRANCH_NAME}",
            "--pull --label BUILD_URL=${env.BUILD_URL} ."
          )
        }
      }
    }
    stage('Test image') {
      steps {
        script {
          dockerImage.inside {
            sh 'echo "INSIDE CONTAINER!"'
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
        sh '/usr/bin/docker rmi ${env.imageName}:${env.BRANCH_NAME}'
      }
    }
  }
}

