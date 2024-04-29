pipeline {
    
    agent any  

    stages {
        stage('Check Permissions') {
            steps {
                sh 'pwd'
                sh 'ls -lha'
            }
        }
        stage('Checkmarx') {
            steps {
                echo 'Checkmarx'
                checkmarxASTScanner additionalOptions: '--project-groups My-POC-Group --scan-types sast --report-format pdf', baseAuthUrl: '', branchName: '', checkmarxInstallation: 'cx', credentialsId: '', projectName: 'jenkins-pipeline', serverUrl: '', tenantName: ''
            }
        }

        stage('Test') {
            steps {
                echo 'test stage'
                echo '******************************'
            }
        }
    }
}