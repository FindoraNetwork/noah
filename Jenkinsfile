pipeline {

  environment {
    dockerRepo = 'https://nexus.findora.org'
    dockerCreds = 'nexus'
    dockerName = 'zei'
  }

  agent any

  options {
    ansiColor('xterm')
  }

  stages {
    stage('Prep') {
      steps {
        script {
          sh 'bash ./scripts/docker_prep.sh'
        }
      }
    }

    stage('Build') {
      steps {
        script {
          docker.withRegistry( dockerRepo, dockerCreds ) {
            dockerImage = docker.build( dockerName + ":" + env.BRANCH_NAME, '--pull .')
          }
        }
      }
    }

    stage('Push') {
      when {
        branch 'master'
      }
      steps {
        script {
          docker.withRegistry( dockerRepo, dockerCreds ) {
            dockerImage.push()
          }
        }
      }
    }

  }

}
