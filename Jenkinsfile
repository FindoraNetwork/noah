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
          sh 'patch < Cargo.Dockerpatch'
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

    stage('Audit + Test') {
      steps {
        script {
          sh "echo 'RUN cargo audit' >> Dockerfile"
          sh "echo 'RUN cargo test' >> Dockerfile"
          docker.withRegistry( dockerRepo, dockerCreds ) {
            testImage = docker.build( dockerName + ":test-" + env.BRANCH_NAME, '--pull .')
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
