import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QFileDialog, QMessageBox, QGroupBox)
from PyQt5.QtCore import Qt
from aes_file_crypto import AESFileCrypto
import os

class FileCryptoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES-256 File Encryption Tool")
        self.setGeometry(100, 100, 500, 300)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)
        
        self.create_password_group()
        self.create_file_group()
        self.create_action_buttons()
        
    def create_password_group(self):
        group = QGroupBox("Password")
        layout = QVBoxLayout()
        
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.Password)
        
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.password_edit)
        layout.addWidget(QLabel("Confirm Password:"))
        layout.addWidget(self.confirm_password_edit)
        
        group.setLayout(layout)
        self.layout.addWidget(group)
    
    def create_file_group(self):
        group = QGroupBox("File Operations")
        layout = QVBoxLayout()
        
        self.input_file_edit = QLineEdit()
        self.output_file_edit = QLineEdit()
        
        file_button_layout = QHBoxLayout()
        self.browse_input_btn = QPushButton("Browse Input")
        self.browse_output_btn = QPushButton("Browse Output")
        file_button_layout.addWidget(self.browse_input_btn)
        file_button_layout.addWidget(self.browse_output_btn)
        
        layout.addWidget(QLabel("Input File:"))
        layout.addWidget(self.input_file_edit)
        layout.addWidget(QLabel("Output File (optional):"))
        layout.addWidget(self.output_file_edit)
        layout.addLayout(file_button_layout)
        
        group.setLayout(layout)
        self.layout.addWidget(group)
        
        # Connect buttons
        self.browse_input_btn.clicked.connect(self.browse_input_file)
        self.browse_output_btn.clicked.connect(self.browse_output_file)
    
    def create_action_buttons(self):
        button_layout = QHBoxLayout()
        
        self.encrypt_btn = QPushButton("Encrypt")
        self.decrypt_btn = QPushButton("Decrypt")
        
        button_layout.addWidget(self.encrypt_btn)
        button_layout.addWidget(self.decrypt_btn)
        
        self.layout.addLayout(button_layout)
        
        # Connect buttons
        self.encrypt_btn.clicked.connect(self.encrypt_file)
        self.decrypt_btn.clicked.connect(self.decrypt_file)
    
    def browse_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if file_path:
            self.input_file_edit.setText(file_path)
            # Suggest output filename
            if not self.output_file_edit.text():
                if self.sender() == self.browse_input_btn:
                    self.output_file_edit.setText(file_path + '.enc')
    
    def browse_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Select Output File")
        if file_path:
            self.output_file_edit.setText(file_path)
    
    def validate_inputs(self):
        password = self.password_edit.text()
        confirm = self.confirm_password_edit.text()
        input_file = self.input_file_edit.text()
        
        if not password:
            QMessageBox.warning(self, "Warning", "Password cannot be empty!")
            return False
        
        if password != confirm:
            QMessageBox.warning(self, "Warning", "Passwords do not match!")
            return False
        
        if not os.path.isfile(input_file):
            QMessageBox.warning(self, "Warning", "Input file does not exist!")
            return False
        
        return True
    
    def encrypt_file(self):
        if not self.validate_inputs():
            return
        
        try:
            crypto = AESFileCrypto(self.password_edit.text())
            input_file = self.input_file_edit.text()
            output_file = self.output_file_edit.text() or input_file + '.enc'
            
            if crypto.encrypt_file(input_file, output_file):
                QMessageBox.information(self, "Success", "File encrypted successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {str(e)}")
    
    def decrypt_file(self):
        if not self.validate_inputs():
            return
        
        try:
            crypto = AESFileCrypto(self.password_edit.text())
            input_file = self.input_file_edit.text()
            output_file = self.output_file_edit.text()
            
            if not output_file:
                if input_file.endswith('.enc'):
                    output_file = input_file[:-4]
                else:
                    output_file = input_file + '.dec'
            
            if crypto.decrypt_file(input_file, output_file):
                QMessageBox.information(self, "Success", "File decrypted successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = FileCryptoGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
