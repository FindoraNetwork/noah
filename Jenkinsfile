pipeline {

  environment {
    dockerRepo = 'https://563536162678.dkr.ecr.us-west-2.amazonaws.com'
    dockerCreds = 'ecr:us-west-2:aws-jenkins'
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
