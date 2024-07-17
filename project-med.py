import json
import dropbox
from functools import wraps
import hashlib  
from ipfshttpclient import Client
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from brownie import accounts, project, network
from cryptography.fernet import Fernet
from datetime import datetime
import base64
import requests
import speedtest
import time

def measure_upload_speed():
    st = speedtest.Speedtest()
    st.get_best_server()

    return st.upload() / 1_000_000  # Convert to Mbps

def execution_time_decorator(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        duration = end_time - start_time

        print(f"Start Time: {start_time}")
        print(f"End Time: {end_time}")
        print(f"Duration: {duration} seconds")

        return result

    return wrapper


def main():
    # Set Ganache as the active network
    try:
        network.connect("development")
    except ConnectionError:
        pass

if __name__ == "__main__":
    main()
    

def only_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        admin_address = contract.admin()
        caller_account = accounts[args[0]].address
        assert admin_address == caller_account, "Only the admin can call this function"
        return fn(*args, **kwargs)
    return wrapper

def only_patient(func):
    @wraps(func)
    def wrapper(caller_account, *args, **kwargs):
        # Verify that the caller is an active patient
        assert contract.patient(accounts[caller_account])[0], "Caller is not an active patient"
        return func(caller_account, *args, **kwargs)
    return wrapper

def only_pharmacy(func):
    @wraps(func)
    def wrapper(caller_account, *args, **kwargs):
        # Verify the caller meets the required conditions
        assert contract.pharmacy(accounts[caller_account]), "Caller is not a valid pharmacy"
        # Call the original function
        return func(caller_account, *args, **kwargs)

    return wrapper


def load_project(project_name):
    loaded_projects = project.get_loaded_projects()
    if project_name in loaded_projects:
        return loaded_projects[project_name]
    else:
        return project.load(project_name)

project_name = "MyProject"
loaded_project = load_project(project_name)

mycontract = loaded_project.Med

def deploy_contract():
    contract = mycontract.deploy({'from': accounts[0]})
    return contract

contract = deploy_contract()

# Generate RSA key pair
self_private_key, self_public_key = [], []

def generate_rsa_key_pair(count=0):
    global self_private_key, self_public_key
    for i in range(count):
        # Generate RSA key pair if not already generated
        key = RSA.generate(2048)
        self_private_key.append(key.export_key().decode('ascii'))
        self_public_key.append(key.publickey().export_key().decode('ascii'))
            
        # Push RSA Public Key into blockchain
        contract.setPublicKey(self_public_key[i], {'from':accounts[i]})
    

def encrypt_and_upload_image(image_path):
    # Connect to IPFS
    client = Client()

    # Read the image file
    with open(image_path, 'rb') as file:
        image_data = file.read()

    # Generate a symmetric key
    key = Fernet.generate_key()
    fernet = Fernet(key)

    # Encrypt the image
    encrypted_image = fernet.encrypt(image_data)

    # Upload the encrypted image to IPFS
    encrypted_image_hash = client.add_bytes(encrypted_image)

    # Convert the key and hash to base64 strings for easy storage
    encoded_key = base64.b64encode(key).decode('utf-8')
    encoded_hash = encrypted_image_hash
    
    # Return the key and IPFS hash
    return encoded_key, encoded_hash

def decrypt_and_download_image(ipfs_hash, key):
    # Connect to IPFS
    client = Client()

    # Retrieve the encrypted image from IPFS
    encrypted_image = client.cat(ipfs_hash)

    # Decode the base64-encoded key
    decoded_key = base64.b64decode(key)

    # Decrypt the image
    fernet = Fernet(decoded_key)
    decrypted_image = fernet.decrypt(encrypted_image)

    # Save the decrypted image locally
    image_path = r'/decrypted_image.jpg'
    with open(image_path, 'wb') as file:
        file.write(decrypted_image)

    # Return the file path
    return image_path

access_token = "sl.BlOqLkD6cH_2yAA3nWtpe2LATYmLIPZUBaPEgFAApLz16uzntzcQAGz5Wq56bO4nvx-3sQIXmAyLObNXCgNt3EYnf5IsWsnSZb1WIxqwQIXeHGkJ8uMBURe7GF-QhwWgY6p2aVCOSXDbgQk"
destination_folder = "/docs"

def push_dropbox_data(data, target_address):
    try:

        # Generate a Fernet key
        fernet_key = Fernet.generate_key()

        # Create a Fernet instance with the generated key
        fernet = Fernet(fernet_key)

        # Encrypt the data using Fernet
        encrypted_data = fernet.encrypt(json.dumps(data).encode())

        # Connect to Dropbox API
        dbx = dropbox.Dropbox(access_token)
        
        # Specify the upload mode to overwrite existing files
        upload_mode = dropbox.files.WriteMode.overwrite

        # Upload the encrypted data to Dropbox
        file_path = f"{destination_folder}/ipfs.json"
        dbx.files_upload(encrypted_data, file_path, upload_mode)
        
        shared_link = dbx.sharing_create_shared_link(file_path).url

        # Create a dictionary to store the symmetric key and file hash
        key_file_data = {
            'symmetric_key': fernet_key.decode(),
            'file_address': shared_link
        }

        # Convert the key file data to JSON
        key_file_json = json.dumps(key_file_data).encode()
        
        # Encrypt the key file data with the target public key
        target_public_key = RSA.import_key(contract.getPublicKey(target_address))
        cipher = PKCS1_OAEP.new(target_public_key)
        encrypted_key_file = cipher.encrypt(key_file_json)

        # Upload the key file to Dropbox
        key_file_path = f"{destination_folder}/key_file.json"
        dbx.files_upload(encrypted_key_file, key_file_path, upload_mode)
        
        file_link = dbx.sharing_create_shared_link(key_file_path).url

        # Return the file location, Dropbox paths, and the SHA256 hash
        return file_path, file_link

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None, None

def push_ipfs_data(data, target_address):

    # Calculate the SHA256 hash of the data
    hash_value = hashlib.sha256(json.dumps(data).encode()).hexdigest()
    
    # Generate a Fernet key
    fernet_key = Fernet.generate_key()

    # Create a Fernet instance with the generated key
    fernet = Fernet(fernet_key)

    # Encrypt the data using Fernet
    encrypted_data = fernet.encrypt(json.dumps(data).encode())

    # Write the encrypted data to a JSON file
    with open(file_path, 'wb') as json_file:
        json_file.write(encrypted_data)

    # Connect to the IPFS API
    client = Client()

    # Upload the file to IPFS
    res = client.add(file_path)

    # Retrieve the IPFS hash of the uploaded file
    file_hash = res['Hash']

    # Create a dictionary to store the symmetric key and file hash
    key_file_data = {
        'symmetric_key': fernet_key.decode(),
        'file_hash': file_hash
    }

    # Convert the key file data to JSON
    key_file_json = json.dumps(key_file_data).encode()

    # Encrypt the key file data with the target public key
    target_public_key = RSA.import_key(contract.getPublicKey(target_address))
    cipher = PKCS1_OAEP.new(target_public_key)
    encrypted_key_file = cipher.encrypt(key_file_json)

    # Write the encrypted key file data to a JSON file
    key_file_path = file_path + '.key'
    with open(key_file_path, 'wb') as key_file:
        key_file.write(encrypted_key_file)

    # Upload the key file to IPFS
    key_res = client.add(key_file_path)

    # Retrieve the IPFS hash of the key file
    key_file_hash = key_res['Hash']

    # Return the file location, IPFS hash, and key file hash
    return file_path, key_file_hash, hash_value


def pull_link_data(file_link, self_private_key):
    try:
        
        # Get the direct download link for the shared link
        link_parts = file_link.split('?')
        direct_download_link = link_parts[0] + '?dl=1'

        # Download the encrypted data from the direct download link
        response = requests.get(direct_download_link)
        encrypted_data = response.content

        
        # Decrypt the key file content using the private key
        key = RSA.import_key(self_private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_key_file = cipher.decrypt(encrypted_data)

        # Parse the decrypted key file data as JSON
        key_file_data = json.loads(decrypted_key_file.decode())

        # Retrieve the symmetric key and IPFS hash from the key file data
        fernet_key = key_file_data['symmetric_key'].encode()
        data_file_link = key_file_data['file_address']

        # Get the direct download link for the shared link
        link_parts = data_file_link.split('?')
        data_file_link = link_parts[0] + '?dl=1'

        # Download the encrypted data from the direct download link
        response = requests.get(data_file_link)
        encrypted_data = response.content

        # Create a Fernet instance with the symmetric key
        fernet = Fernet(fernet_key)

        # Decrypt the data file content using Fernet
        decrypted_data = fernet.decrypt(encrypted_data)

        # Parse the decrypted data as JSON
        decrypted_json = json.loads(decrypted_data.decode())

        # Return the decrypted data as a dictionary
        return decrypted_json
    
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def pull_ipfs_data(ipfs_hash, self_private_key):
    try:
        # Connect to the IPFS API
        client = Client()

        # Download the encrypted key file from IPFS
        key_file_content = client.cat(ipfs_hash)

        # Decrypt the key file content using the private key
        key = RSA.import_key(self_private_key)
        cipher = PKCS1_OAEP.new(key)
        decrypted_key_file = cipher.decrypt(key_file_content)

        # Parse the decrypted key file data as JSON
        key_file_data = json.loads(decrypted_key_file.decode())

        # Retrieve the symmetric key and IPFS hash from the key file data
        fernet_key = key_file_data['symmetric_key'].encode()
        data_ipfs_hash = key_file_data['file_hash']

        # Download the encrypted data file from IPFS
        encrypted_data = client.cat(data_ipfs_hash)

        # Create a Fernet instance with the symmetric key
        fernet = Fernet(fernet_key)

        # Decrypt the data file content using Fernet
        decrypted_data = fernet.decrypt(encrypted_data)

        # Parse the decrypted data as JSON
        decrypted_json = json.loads(decrypted_data.decode())

        # Return the decrypted data as a dictionary
        return decrypted_json
    
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None
    
def check_signature(data, signature):
    
        # Calculate the SHA256 hash of the data
        hash_value = hashlib.sha256(json.dumps(data).encode()).hexdigest()

        # Verify the hash against the provided signature
        if hash_value != signature:
            print("Signature verification failed")
            return hash_value

# Generate RSA key pair if not already generated
generate_rsa_key_pair(10)
        
# Example dictionary
ehr_data = {
    "Patient Demographics": {
        "Age": 35,
        "Gender": "Male",
        
        "Insurance Information": {
            "Provider": "XYZ Insurance",
            "Policy Number": "123456789"
        }
    },
    "Medication Records": [
        {
            "Medication": "Lisinopril",
            "Dosage": "10 mg",
            "Frequency": "Once daily",
            "Duration": "Ongoing"
        },
        {
            "Medication": "Metformin",
            "Dosage": "1000 mg",
            "Frequency": "Twice daily",
            "Duration": "Ongoing"
        }
    ],
    
    "Prescription Data": {
    "Patient Information": {
        "Age": 35,
    },
    "Prescriber Information": {
        "Full Name": "Dr. Jane Doe",
        "Wallet Address": "0x21b42413bA931038f35e7A5224FaDb065d297Ba3",
        "Credentials": "MD",
        "Contact Information": {
            "Phone": "555-9876",
            "Email": "jane.doe@example.com"
        },
        "License Number": "ABCD1234"
    },
    "Date": "2023-06-27",
    "Medication Name": "Acetaminophen",
    "Dosage Instructions": {
        "Dosage": "500 mg",
        "Frequency": "Every 6 hours",
        "Duration": "7 days"
    },
    "Route of Administration": "Oral",
    "Quantity": "20 tablets",
    "Prescriber's Contact Information": {
        "Phone": "555-9876",
        "Office Address": "123 Main St, City, State, ZIP"
    },
    "Special Instructions or Additional Information": "Take with food if experiencing stomach discomfort."
}
    ,
    "Lab and Diagnostic Test Results": {
        "Blood Test": {
            "Hemoglobin": 14.5,
            "Glucose": 110,
            "Cholesterol": 180
        },
        "Symmetric Key":"OFkxY20zcmc4UUh1STlldmlPcENJY2Ftc05DSXdpRHNfM29aVkFLa0lMUG0=",
        "Imaging Studies IPFS": "Qmf2fBrCZYvhbg251mtSMKymBVLeP7kHYySJaXnBpWaKYj",
        "Pathology Reports": ["Biopsy of skin lesion"]
    },
    "Vital Signs": {
        "Blood Pressure": "120/80 mmHg",
        "Heart Rate": 75,
        "Respiratory Rate": 16,
        "Temperature": 98.6,
        "Oxygen Saturation": 98
    },
    "Progress Notes": [
        {
            "Date": "2023-06-01",
            "Symptoms": "Headache, dizziness",
            "Observations": "Elevated blood pressure",
            "Treatment Plan": "Increased Lisinopril dosage"
        },
        {
            "Date": "2023-06-15",
            "Symptoms": "Fatigue",
            "Observations": "Well-controlled blood glucose",
            "Treatment Plan": "Continued Metformin"
        }
    ],
    "Care Plans": {
        "Hypertension": "Lifestyle modifications, medication",
        "Diabetes": "Blood sugar monitoring, medication, diet"
    },

}


# Specify the file path
file_path = r'C:\Users\arman\OneDrive\Desktop\MyProject/ipfs.json'

@only_admin
def call_addDoctor(caller_account, doctor_address):
    # Call the 'addDoctor' function in the contract
    contract.addDoctor(doctor_address, {'from': accounts[caller_account]})
    
@only_admin
def call_removeDoctor(caller_account, doctor_address):
    # Call the 'addDoctor' function in the contract
    contract.removeDoctor(doctor_address, {'from': accounts[caller_account]})
    
@only_admin
def call_addPatient(caller_account, patient_address):
    # Call the 'addDoctor' function in the contract
    contract.addPatient(patient_address, {'from': accounts[caller_account]})
    
@only_admin
def call_addPharmacy(caller_account, pharmacy_address):
    # Call the 'addDoctor' function in the contract
    contract.addPharmacy(pharmacy_address, {'from': accounts[caller_account]})
    
@only_admin
def call_removePharmacy(caller_account, pharmacy_address):
    # Call the 'addDoctor' function in the contract
    contract.removePharmacy(pharmacy_address, {'from': accounts[caller_account]})
    
def call_approveDoctor(caller_account, patient_address, doctor_address):
    """
    Approves a doctor for a patient in the contract.

    Parameters:
    - patient_address: The address of the patient.
    - doctor_address: The address of the doctor to be approved.
    - caller_account: The address of the caller.

    Note: The caller must meet certain requirements to successfully approve the doctor.
    """

    # Verify the caller meets the required conditions
    assert (
        ((contract.patient(accounts[caller_account])[0] and patient_address == accounts[caller_account])) or
        contract.getPatientApprovedTrustee(patient_address, accounts[caller_account])
    ), "Caller does not meet the required conditions"
    
    # Check if the doctor is active
    assert contract.doctor(doctor_address)[0], "Doctor is not active"

    # Check for address uniqueness
    assert patient_address != doctor_address and accounts[caller_account] != doctor_address, "Patient and doctor addresses must be unique"

    # Approve the doctor for the patient
    contract.approveDoctor(patient_address, doctor_address, {'from': accounts[caller_account]})
    
def call_revokeDoctor(caller_account, patient_address, doctor_address):
    """
    Revokes the approval of a doctor for a patient in the contract.

    Parameters:
    - caller_account: The address of the caller.
    - patient_address: The address of the patient.
    - doctor_address: The address of the doctor to be revoked.

    Note: The caller must meet certain requirements to successfully revoke the doctor.
    """

    # Verify the caller meets the required conditions
    assert (
        ((contract.patient(accounts[caller_account])[0] and patient_address == accounts[caller_account])) or
        contract.getPatientApprovedTrustee(patient_address, accounts[caller_account])
    ), "Caller does not meet the required conditions"

    # Revoke the doctor's approval for the patient
    contract.revokeDoctor(patient_address, doctor_address, {'from': accounts[caller_account]})
    
@only_patient
def call_deleteRecord(caller_account, index):
    """
    Deletes a medical record permanently for the patient in the contract.

    Parameters:
    - caller_account: The address of the caller (patient).
    - index: The index of the medical record to be deleted.

    Note: Only an active patient can delete their medical records.
    """

    # Delete the medical record permanently
    contract.deleteRecord(index, {'from': accounts[caller_account]})
    
@only_patient
def call_approveTrustee(caller_account, trustee_address):
    """
    Approval of a trustee for the patient in the contract.

    Parameters:
    - caller_account: The address of the caller (patient).
    - trustee_address: The address of the trustee to be revoked.
    """
    assert accounts[caller_account] != trustee_address
    
    # Revoke the trustee's approval for the patient
    contract.approveTrustee(trustee_address, {'from': accounts[caller_account]})
    
@only_patient
def call_revokeTrustee(caller_account, trustee_address):
    """
    Revokes the approval of a trustee for the patient in the contract.

    Parameters:
    - caller_account: The address of the caller (patient).
    - trustee_address: The address of the trustee to be revoked.
    """

    # Revoke the trustee's approval for the patient
    contract.revokeTrustee(trustee_address, {'from': accounts[caller_account]})
    
def call_setAllowedDoc(caller_account, patient_address, document_address):
    """
    Sets the allowed hash to be viewed by a doctor for the patient in the contract.

    Parameters:
    - caller_account: The address of the caller.
    - patient_address: The address of the patient.
    - doc_address: The hash address to be set as allowed.

    Note: The caller must meet certain requirements to successfully set the allowed hash.
    """

    # Verify the caller meets the required conditions
    assert (
        ((contract.patient(accounts[caller_account])[0] and patient_address == accounts[caller_account])) or
        contract.getPatientApprovedTrustee(patient_address, accounts[caller_account])
    ), "Caller does not meet the required conditions"

    # Set the allowed hash for the patient
    contract.setAllowedDoc(patient_address, document_address, {'from': accounts[caller_account]})

def call_setAllowedPrescription(caller_account, patient_address, pres_address):
    """
    Sets the allowed hash to be viewed by a pharmacy for the patient in the contract.

    Parameters:
    - caller_account: The address of the caller.
    - patient_address: The address of the patient.
    - pres_address: The hash address to be set as allowed.

    Note: The caller must meet certain requirements to successfully set the allowed hash.
    """

    # Verify the caller meets the required conditions
    assert (
        ((contract.patient(accounts[caller_account])[0] and patient_address == accounts[caller_account])) or
        contract.getPatientApprovedTrustee(patient_address, accounts[caller_account])
    ), "Caller does not meet the required conditions"

    # Set the allowed hash for the patient
    contract.setAllowedPrescription(patient_address, pres_address, {'from': accounts[caller_account]})

@only_patient
def call_setAllowedDocument(caller_account, trustee_address, doc_address):
    """
    Sets the allowed hash to be viewed by a trustee for the patient in the contract.

    Parameters:
    - caller_account: The address of the caller (patient).
    - trustee_address: The address of the trustee.
    - doc_address: The hash address to be set as allowed.

    Note: Only an active patient can set the allowed hash for a trustee.
    """

    # Set the allowed hash for the trustee
    contract.setAllowedDocument(trustee_address, doc_address, {'from': accounts[caller_account]})
    
def call_setMedicalRecord(
    caller_account,
    patient_address,
    timestamp,
    document_hash,
    pres_ipfs,
    pres_hash,
    med_ipfs,
    rom,
    soi,
    duration
):
    """
    Sets the medical record for the patient in the contract.

    Parameters:
    - caller_account: The address of the caller (doctor).
    - patient_address: The address of the patient.
    - timestamp: The timestamp of the medical record.
    - document_hash: The hash of the document.
    - pres_ipfs: The IPFS address of the prescription.
    - pres_hash: The hash of the prescription.
    - med_ipfs: The IPFS address of the medical record.
    - rom: The rate of medical record completeness.
    - soi: The rate of significance of the information.
    - duration: The duration of the medical record.

    Note: Only an approved doctor can set the medical record for the patient.
    """

    # Verify that the caller is an approved doctor for the patient
    # assert contract.checkApprovedDoctor(patient_address, {'from':accounts[caller_account]), "Caller is not an approved doctor for the patient"

    # Perform additional validations
    assert 4 >= rom >= 1, "Invalid value for rate of medical record completeness (ROM)"
    assert 4 >= soi >= 1, "Invalid value for rate of significance of information (SOI)"
    assert 90 >= duration >= 3, "Invalid value for duration"

    # Set the medical record and related details
    contract.setMedicalRecord(
        patient_address,
        timestamp,
        document_hash,
        pres_ipfs,
        pres_hash,
        med_ipfs,
        rom,
        soi,
        duration,
        {'from': accounts[caller_account]}
    )

@only_pharmacy
def call_setPrescriptionState(caller_account, patient_address, index):
    """
    Sets the state of the prescription after it's delivered to the patient in the contract.

    Parameters:
    - patient_address: The address of the patient.
    - index: The index of the medical record.
    - pharmacy_address: The address of the pharmacy performing the action.
    """

    # Verify the caller meets the required conditions
    assert contract.pharmacy(accounts[caller_account]), "Caller is not a valid pharmacy"

    # Set the prescription state
    contract.setPrescriptionState(patient_address, index, {'from': accounts[caller_account]})
    
def call_getDoctorToBeVoted(caller_account):
    """
    Retrieves the address of the next doctor to be voted for by the patient.

    Parameters:
    - caller_account: The address of the caller (patient).

    Returns:
    - doctor_address: The address of the next doctor to be voted for.
    """

    # Retrieve the doctor address to be voted for
    doctor_address = contract.getDoctorToBeVoted({'from': accounts[caller_account]})

    return doctor_address

def call_getDoctorScore(doctor_address, caller_account):
    """
    Retrieves the reputation score of a doctor.

    Parameters:
    - doctor_address: The address of the doctor.
    - caller_account: The address of the caller.

    Returns:
    - rep_score: The reputation score of the doctor.
    """

    # Retrieve the reputation score of the doctor
    rep_score = contract.getDoctorScore(doctor_address, {'from': accounts[caller_account]})

    return rep_score

@only_patient
def call_getPrescription_patient( caller_account, index):
    """
    Retrieves the prescription for a given index.

    Parameters:
    - index: The index of the prescription.
    - caller_account: The address of the caller (patient).

    Returns:
    - prescription_ipfs: The IPFS hash of the prescription.
    """

    # Retrieve the prescription IPFS hash
    prescription_ipfs = contract.getPrescription(index, {'from': accounts[caller_account]})

    return prescription_ipfs

def call_getPrescription_pharmacy(patient_address, index, caller_account):
    """
    Retrieves the prescription details for a given patient and index.

    Parameters:
    - patient_address: The address of the patient.
    - index: The index of the prescription.
    - caller_account: The address of the caller (pharmacy).

    Returns:
    - prescription_hash: The hash of the prescription.
    - doctor_address: The address of the doctor who prescribed the medication.
    - allowed_prescription: The description of the allowed prescription.
    """

    # Retrieve the prescription details
    prescription = contract.getPrescription(patient_address, index, {'from': accounts[caller_account]})

    prescription_hash, doctor_address, allowed_prescription = prescription

    return prescription_hash, doctor_address, allowed_prescription

def call_getPatientDiagnosisCount(patient_address):
    """
    Retrieves the count of diagnoses for a patient.

    Parameters:
    - patient_address: The address of the patient.

    Returns:
    - diagnosis_count: The count of diagnoses for the patient.
    """

    # Retrieve the diagnosis count
    diagnosis_count = contract.getPatientDiagnosisCount(patient_address)

    return diagnosis_count

def call_getPatientApprovedDoctor(patient_address, doctor_address):
    """
    Retrieves the approval status of a doctor for a patient.

    Parameters:
    - patient_address: The address of the patient.
    - doctor_address: The address of the doctor.

    Returns:
    - approved: Boolean indicating whether the doctor is approved for the patient.
    """

    # Retrieve the approval status
    approved = contract.getPatientApprovedDoctor(patient_address, doctor_address)

    return approved

def call_getPatientApprovedTrustee(patient_address, trustee_address):
    """
    Retrieves the approval status of a doctor for a patient.

    Parameters:
    - patient_address: The address of the patient.
    - trustee_address: The address of the trustee.

    Returns:
    - approved: Boolean indicating whether the trustee is approved for the patient.
    """

    # Retrieve the approval status
    approved = contract.getPatientApprovedTrustee(patient_address, trustee_address)

    return approved

@only_pharmacy
def pull_prescription_by_pharmacy(caller_account, patient_address):
    
    file_link = contract.getPatientAllowedPrescription(accounts[1], {'from':accounts[caller_account]})
    index = contract.getPateintAllowedPrescriptionIndex(accounts[1], {'from':accounts[caller_account]})

    decrypted_json = pull_link_data(file_link, self_private_key[caller_account])
    
    signature, doctor_address, _ = contract.getPrescription(patient_address, index, {'from':accounts[caller_account]})

    check_signature(decrypted_json, signature)
    
    return decrypted_json
    
def pull_prescription_by_patient(caller_account, index):

    # Pull the ipfs hash of prescription from Blockchain
    ipfs_hash, signature = contract.getPrescription(index, {'from':accounts[caller_account]})
    
    # Pull theprescription from ipfs
    data = pull_ipfs_data(ipfs_hash, self_private_key[caller_account])
    
    # Verify the signature
    check_signature(data, signature)
        
    return data, index

def push_prescription_by_patient(caller_account, index, data, pharmacy_address):
    
    '''
    We may use http address here so that the data will be available temporarily and after one
    time use, user can delete it from the cloud
    '''
    
    document_path, pres_address = push_dropbox_data(data, pharmacy_address)
    
    # Push the prescription details into blockchain
    contract.setAllowedPrescription(accounts[caller_account], pres_address, index, {'from':accounts[caller_account]})

def pull_document_by_doctor(caller_account, patient_address):
        
    file_link = contract.getMedicalRecord(patient_address, {'from':accounts[caller_account]})
    
    decrypted_json = pull_link_data(file_link, self_private_key[caller_account])
    
    timestamp = decrypted_json['timestamp']
    
    signature = contract.getMedicalDocumentHash( timestamp, patient_address, {'from':accounts[caller_account]})
    check_signature(decrypted_json, signature)
    
    return decrypted_json

def pull_document_by_patient(caller_account, index):

    # Pull the ipfs hash of prescription from Blockchain
    ipfs_hash = contract.getMedicalDocument(index, {'from':accounts[caller_account]})
    
    # Pull theprescription from ipfs
    data = pull_ipfs_data(ipfs_hash, self_private_key[caller_account])
    
    timestamp = data['timestamp']  
    signature = contract.getMedicalDocumentHash(timestamp, accounts[caller_account], {'from':accounts[caller_account]})
    
    # Verify the signature
    check_signature(data, signature)
        
    return data

def push_document_by_patient(caller_account,patient_address, data, doctor_address):
    
    '''
    We may use http address here so that the data will be available temporarily and after one
    time use, user can delete it from the cloud
    '''
    
    document_path, document_address = push_dropbox_data(data, doctor_address)
    
    # Push the prescription details into blockchain
    contract.setAllowedDoc(patient_address ,document_address, {'from':accounts[caller_account]})

def push_document_by_patient_for_trustee(caller_account, data, trustee_address):
    
    '''
    We may use http address here so that the data will be available temporarily and after one
    time use, user can delete it from the cloud
    '''
    
    document_path, document_address = push_dropbox_data(data, trustee_address)
    
    # Push the prescription details into blockchain
    contract.setAllowedDocument(trustee_address,document_address, {'from':accounts[caller_account]})

def pull_document_by_trustee(caller_account, patient_address):
        
    file_link = contract.getAllowedDocument(patient_address, {'from':accounts[caller_account]})
    
    decrypted_json = pull_link_data(file_link, self_private_key[caller_account])
    
    timestamp = decrypted_json['timestamp']
    
    signature = contract.getMedicalDocumentHash( timestamp, patient_address, {'from':accounts[caller_account]})
    check_signature(decrypted_json, signature)
    
    return decrypted_json

def test_ipfs_push(target_account):
    global file_location, ipfs_hash, signature
    
    # Call the create() function
    file_location, ipfs_hash, signature = push_ipfs_data(ehr_data, accounts[target_account], file_path)
    
    if file_location and ipfs_hash:
        print("JSON file created and uploaded successfully!")
        print("File Location:", file_location)
        print("IPFS Hash:", ipfs_hash)
    else:
        print("Failed to create the JSON file or upload it to IPFS.")
        
    return file_location, ipfs_hash, signature

def test_ipfs_pull(caller_account):
    # Call the pull() function
    decrypted_data = pull_ipfs_data(ipfs_hash, self_private_key[caller_account], signature)
    
    if decrypted_data:
        print("File pulled and decrypted successfully!")
        print("Decrypted Data:", decrypted_data)
    else:
        print("Failed to pull and decrypt the file.")
        
@execution_time_decorator
def upload_medical_doc(caller_account, data, patient_address):

    assert contract.checkApprovedDoctor(accounts[caller_account], patient_address)
        
    # Get the current timestamp
    timestamp = datetime.now()
    
    # Convert the timestamp to a string
    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    
    # Add timestamp to medical data
    data['timestamp'] = timestamp_str
    
    # push medical document into ipfs and retrieve hash
    med_location, med_ipfs_hash, med_hash_value = push_ipfs_data(ehr_data, patient_address)
    
    # Add timestamp to prescription data
    prescription_data = dict(data['Prescription Data'])
    prescription_data['timestamp'] = timestamp_str
    
    # push prescription document into ipfs and retrieve hash
    pres_location, pres_ipfs_hash, pres_hash_value = push_ipfs_data(prescription_data, patient_address)
    
    # Add medical document data to blockchain  
    call_setMedicalRecord(caller_account, patient_address, timestamp_str, med_hash_value, pres_ipfs_hash, pres_hash_value, med_ipfs_hash, 3, 2, 60) 
    
    return med_location, med_ipfs_hash, med_hash_value, pres_location, pres_ipfs_hash, pres_hash_value
           
@only_patient
def vote(caller_account):
    msg = contract.getDoctorToBeVoted({'from':accounts[caller_account]})
    print(f'You are about to sumbit a score for this address: {msg}')
    score = int(input('Please sumbit your score: '))
    contract.vote(score, {'from':accounts[caller_account]})
    
    
admin = accounts[0]
pat1 = accounts[1]
pat2 = accounts[2]
doc1 = accounts[3]
doc2 = accounts[4]
pharm1 = accounts[5]
pharm2 = accounts[6]
call_addDoctor(0, doc1)
call_addDoctor(0, doc2)
call_addPatient(0, pat1)
call_addPatient(0, pat2)
contract.addPharmacy(pharm1, {'from':accounts[0]})
contract.addPharmacy(pharm2, {'from':accounts[0]})
call_approveDoctor(1, pat1, doc1)


