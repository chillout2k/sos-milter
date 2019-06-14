pipeline {
  agent any

  parameters {
    string defaultValue: 'https', name: 'dockerRegistryScheme', trim: true
    string defaultValue: 'change.me', name: 'dockerRegistryRepo', trim: true
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
          docker.withRegistry("${env.dockerRegistryScheme}://${env.dockerRegistryRepo}") {
            dockerImage.push()
          }
        }
      }
    }
    stage('Cleanup') {
      steps {
        sh '/usr/bin/docker rmi -f "${imageName}:${BRANCH_NAME}"'
        sh '/usr/bin/docker rmi -f "${dockerRegistryRepo}/${imageName}:${BRANCH_NAME}"'
      }
    }
  }
}

