def dockerImageObj

pipeline {
  agent any

  parameters {
    string defaultValue: 'https', name: 'dockerRegistryScheme', trim: true
    string defaultValue: 'example.com', name: 'dockerRegistryRepo', trim: true
    string defaultValue: 'sos-milter', name: 'imageName', trim: true
  }

  stages {
    stage('Build image') {
      steps {
        sh '/usr/bin/env'
        script {
          dockerImageObj = docker.build(
            "${env.imageName}:${env.BRANCH_NAME}",
            "--pull --label BUILD_URL=${env.BUILD_URL} ."
          )
        }
      }
    }
    stage('Test image') {
      steps {
        script {
          dockerImageObj.inside() {
            sh 'echo "INSIDE CONTAINER!"'
            sh '/usr/bin/python3 /app/sos-milter.py &'
            sh 'sleep 5; if [ -S /socket/sos-milter ]; then exit 0; else exit 1; fi'
          }
        }
      }
    }
    stage('Push image') {
      steps {
        script {
          docker.withRegistry("${env.dockerRegistryScheme}://${env.dockerRegistryRepo}") {
            dockerImageObj.push()
          }
        }
      }
    }
    stage('Cleanup') {
      steps {
        echo "Cleanup"
        /* The default is to reuse the local images for future builds. The reason 
           for this is quite simple! It´s much easier to prune local images from
           disk than pushed images from the (cheap) docker registry! */
        /* Uncomment the following directives if you want your build host to stay
           clean from local docker images after successfull push. But, there is a 
           caveat if you do so! Each build job produces at least one new image layer 
           which gets pushed to the registry. This could blow up your registry after
           a couple of time! For garbage collection check this out: 
           https://docs.docker.com/registry/garbage-collection/ */
        /* echo "Remove local docker images after successfull push to registry..." */
        /* sh '/usr/bin/docker rmi -f "${imageName}:${BRANCH_NAME}"' */
        /* sh '/usr/bin/docker rmi -f "${dockerRegistryRepo}/${imageName}:${BRANCH_NAME}"' */
      }
    }
  }
}

