// SPDX-License-Identifier: MIT
// A year

pragma solidity ^0.8.4;

contract Med {

    // ### VARIABLES SECTION ###

    address public admin; // Admin of contract

    struct _medinfo {
        string medical_ipfs; // latest medical document
        string prescription_ipfs; // latest prescription ipfs file hash
        string prescription_hash; // prescription document hash - to be checked for equality with hash of the document provided to pharmacy
        bool prescription_received; // Either true or false
        address doctor_address; 
    }

    struct _diagnosis {
        uint ROM; // Risk of mortality
        uint SOI; // Severity of illness
        uint duration; // treatment duration
        uint visit_date;
        address doctor_address;
    }

    struct _approved_trustee {
        bool active;
        string document_link; // IPFS Doc hash for trustee - This could also be a cloud link
    }

    struct _patient {
        // Every Detail needed to be stored about patients

        bool active; // state of patient
        uint medinfo_position; // A position holder for medinfo mapping
        string allowed_doc; // A temporary medical hash availabe for doctor to see - - This could also be a cloud link
        string allowed_prescription; // To store the allowed prescription
        uint allowed_prescription_index; // to store the allowed prescription index
        mapping(string => bool) allergy; // to store patient allergies
        mapping(string => bool) surgery; // to store patient surgeries
        mapping(string => bool) immunization; // to store pateints Immunization
        _diagnosis [] diagnosis; // A temporary list consisting of medical diagnosis used to calculate rep_score
        mapping(address => bool) new_vote_disabled; // state of patients voting condition
        mapping(address => _approved_trustee) approved_trustees; // A mapping for patient's approved trustees
        mapping(address => bool) approved_doctors; // A mapping for patinet's temporary approved doctors
        mapping(uint => _medinfo) medinfo; // A struct to store medical information
        
    }

    struct _doctor {
        bool active; // State of doctor
        uint rep_score; // Overall reputation score
        uint vote_count; // Number of Votes
        uint [] score_history;
    }

    mapping(address => _patient) public patient; // A mapping to _patient struct - used to store everything patient related
    mapping(address => _doctor) public doctor; // A mapping for _doctor struct - used to store everything patient related
    mapping(address => bool) public pharmacy; // A mapping for pharmacy addresses verified by Admin
    mapping(address => string) public_key; // Public keys mapping
    mapping(address => mapping(string => string)) private med_doc_hash; // A mapping to store medical document hashes

    // ### END VARIABLES SECTION ###
    // ### CONSTRUCTOR SECTION ###

    constructor() {
        // Initialize Address

        admin = msg.sender;
    }

    // ### END CONSTRUCTOR SECTION ###
    // ### MODIFIERS SECTION ###

    modifier onlyAdmin{
        require(msg.sender == admin);
        _;
    }

    modifier onlyPatient{
        require(patient[msg.sender].active);
        _;
    }

    modifier onlyApprovedDoctor(address patient_address){
        require(patient[patient_address].approved_doctors[msg.sender]);
        _;
    }

    modifier onlyPharmacy(address pharmacy_address){
        require(pharmacy[pharmacy_address]);
        _;
    }

    modifier onlyAfter(uint time_now, address patient_address){
        // runs the function only if the duration is passed

        if(patient[patient_address].diagnosis.length > 0){
            require(time_now > (patient[patient_address].diagnosis[patient[patient_address].diagnosis.length -1].visit_date +
            (patient[patient_address].diagnosis[patient[patient_address].diagnosis.length -1].duration) * 1 days), 'Too Soon!');
        }
        _;
    }

    modifier onlyBefore(uint time_now, address patient_address){
        // runs the function only if the duration is not passed

        if(patient[patient_address].diagnosis.length > 0){
            require(time_now <= (patient[patient_address].diagnosis[patient[patient_address].diagnosis.length -1].visit_date +
            (patient[patient_address].diagnosis[patient[patient_address].diagnosis.length -1].duration) * 1 days), 'Too Late!');
        }
        _;
    }


    // ### END MODIFIERS SECTION ###

    function getPatientActive(address patientAddress) public view returns (bool) {
        return patient[patientAddress].active;
    }

    function getPatientMedinfoPosition(address patientAddress) public view returns (uint) {
        return patient[patientAddress].medinfo_position;
    }

    function getPatientAllowedDoc(address patientAddress) public onlyApprovedDoctor(msg.sender) view returns (string memory) {
        return patient[patientAddress].allowed_doc;
    }

    function getPatientAllowedPrescription(address patientAddress) public onlyPharmacy(msg.sender) view returns (string memory) {
        return patient[patientAddress].allowed_prescription;
    }

    function getPateintAllowedPrescriptionIndex(address patientAddress) public onlyPharmacy(msg.sender) view returns (uint) {
        return patient[patientAddress].allowed_prescription_index;
    }

    function getPatientDiagnosisCount(address patientAddress) public view returns (uint) {
        return patient[patientAddress].diagnosis.length;
    }

    function getPatientNewVoteDisabled(address patientAddress, address doctorAddress) public view returns (bool) {
        return patient[patientAddress].new_vote_disabled[doctorAddress];
    }

    function getPatientApprovedTrustee(address patientAddress, address trusteeAddress) public view returns (_approved_trustee memory) {
        return patient[patientAddress].approved_trustees[trusteeAddress];
    }

    function getPatientApprovedDoctor(address patientAddress, address doctorAddress) public view returns (bool) {
        return patient[patientAddress].approved_doctors[doctorAddress];
    }

    function getPatientMedinfo(address patientAddress, uint position) public view returns (_medinfo memory) {
        return patient[patientAddress].medinfo[position];
    }

    // Setter function to add or update an allergy
    function setAllergy(string memory allerg, bool value) public {
        patient[msg.sender].allergy[allerg] = value;
    }

    // Getter function to retrieve the value of an allergy
    function getAllergy(string memory allerg) public view returns (bool) {
        return patient[msg.sender].allergy[allerg];
    }

    // Setter function to add or update a surgery
    function setSurgery(string memory surg, bool value) public {
        patient[msg.sender].surgery[surg] = value;
    }

    // Getter function to retrieve the value of a surgery
    function getSurgery(string memory surg) public view returns (bool) {
        return patient[msg.sender].surgery[surg];
    }

    // Setter function to add or update an immunization
    function setImmunization(string memory immun, bool value) public {
        patient[msg.sender].immunization[immun] = value;
    }

    // Getter function to retrieve the value of an immunization
    function getImmunization(string memory immun) public view returns (bool) {
        return patient[msg.sender].immunization[immun];
    }

    // Setter function to store a medical document hash
    function setMedicalDocumentHash(address _address, string memory key, string memory value) public {
        med_doc_hash[_address][key] = value;
    }

    function getDoctorScore(address doctor_address) public view  onlyAfter(block.timestamp, msg.sender) returns(uint, uint){
        return (doctor[doctor_address].rep_score,doctor[doctor_address].rep_score);
    }

    function getDoctorToBeVoted() public view returns(address){
        // See who is the next doctor you're gonna sumbit a voting for

        return patient[msg.sender].diagnosis[patient[msg.sender].diagnosis.length - 1].doctor_address;
    }

    function finalScore(uint score, address doctor_address) private {
        // recalculate doctor rep_score and store it in a list too

        doctor[doctor_address].rep_score = ((doctor[doctor_address].rep_score * doctor[doctor_address].vote_count) + score)
        / (doctor[doctor_address].vote_count + 1);
        doctor[doctor_address].vote_count += 1;
        doctor[doctor_address].score_history.push(doctor[doctor_address].rep_score);
    }

    function vote(uint _score) public onlyPatient onlyAfter(block.timestamp, msg.sender){
        // voting process by patient 
        require((_score >= 1) && (_score <= 5), 'Rating should be a number from 1 to 5');
        uint score;
        address doctor_address;

        score = _score * 10000;
        doctor_address = patient[msg.sender].diagnosis[patient[msg.sender].diagnosis.length -1].doctor_address;
        patient[msg.sender].new_vote_disabled[doctor_address] = false;
        patient[msg.sender].diagnosis.pop();

        finalScore(score, doctor_address);
    }

    function setMedicalRecord(
        address patient_address,
        string memory timestamp,
        string memory document_hash,
        string memory pres_ipfs,
        string memory pres_hash,
        string memory med_ipfs,
        uint8 _rom,
        uint8 _soi,
        uint duration
        ) onlyApprovedDoctor(patient_address) public {
        // Main function - sets medical record and sets up every detail needed for reputation system

        require((4 >= _rom) && (_rom >= 1));
        require((4 >= _soi) && (_soi >= 1));
        require((90 >= duration) && (duration >= 3));

        // We assign the hashes to certain medinfo index
        patient[patient_address].medinfo[patient[patient_address].medinfo_position].medical_ipfs = med_ipfs;
        patient[patient_address].medinfo[patient[patient_address].medinfo_position].prescription_ipfs = pres_ipfs;
        patient[patient_address].medinfo[patient[patient_address].medinfo_position].prescription_hash = pres_hash;
        patient[patient_address].medinfo[patient[patient_address].medinfo_position].doctor_address = msg.sender;
        med_doc_hash[patient_address][timestamp] = document_hash;

        // Then input diagnosis - these will be stored temporarily 

        // Note that it only happens if there isn't a voting process already in queue

        if(patient[patient_address].new_vote_disabled[msg.sender] == false){
            patient[patient_address].diagnosis.push(_diagnosis(_rom, _soi, duration, block.timestamp, msg.sender));
            patient[patient_address].new_vote_disabled[msg.sender] = true;
        }

        // The doctor should no longer be approved
        patient[patient_address].approved_doctors[msg.sender] = false;

        // Positioner needs to go up by 1
        patient[patient_address].medinfo_position += 1;
    }

    function getMedicalDocumentHash(string memory timestamp, address patient_address) public view returns(string memory){

        return med_doc_hash[patient_address][timestamp];
    }

    function getMedicalDocument(uint index) public view onlyPatient returns(string memory){
        // Get medical record - called by patient

        return patient[msg.sender].medinfo[index].medical_ipfs;
    }

    function getMedicalRecord(address patient_address) public view onlyApprovedDoctor(patient_address) returns(string memory){
        // get medical record - called by doctor

        return patient[patient_address].allowed_doc;
    }

    function getPrescription(uint index) public view onlyPatient returns(string memory, string memory){
        // get prescription - called by patient

        return (patient[msg.sender].medinfo[index].prescription_ipfs,patient[msg.sender].medinfo[index].prescription_hash);

    }

    function getPrescription(address patient_address, uint index) public view onlyPharmacy(msg.sender) returns(string memory, address, string memory) {
        // get prescription hash in case it hasn't been claimed already

        require(patient[patient_address].medinfo[index].prescription_received == false);
        return (patient[patient_address].medinfo[index].prescription_hash,patient[patient_address].medinfo[index].doctor_address,patient[patient_address].allowed_prescription);
    }

    function setPrescriptionState(address patient_address, uint index) public onlyPharmacy(msg.sender) {
        // Set the state of prescrition after it's delievered to patient

        patient[patient_address].medinfo[index].prescription_received = true;
    }

    function deleteRecord(uint index) public onlyPatient {
        // Delete a medical record permamnently

        delete patient[msg.sender].medinfo[index];
    }

    function setAllowedDoc(address patient_address, string  memory doc_address) public {
        // Set allowed hash to be viewed by doctor

        require((patient[msg.sender].active && patient_address == msg.sender) || patient[patient_address].approved_trustees[msg.sender].active);
        patient[patient_address].allowed_doc = doc_address;
    }

    function setAllowedPrescription(address patient_address, string  memory pres_address, uint index) public {
        // Set allowed hash to be viewed by pharmacy

        require((patient[msg.sender].active && patient_address == msg.sender) || patient[patient_address].approved_trustees[msg.sender].active);
        patient[patient_address].allowed_prescription = pres_address;
        patient[patient_address].allowed_prescription_index = index;

    }

    function setAllowedDocument(address trustee_address, string  memory doc_address) public onlyPatient {
        // Set allowed hash to be viewed by trustee

        require(patient[msg.sender].approved_trustees[trustee_address].active);
        patient[msg.sender].approved_trustees[trustee_address].document_link = doc_address;
    }

    function getAllowedDocument(address patient_address) public view returns(string memory) {
        // get allowed hash - viewed by trustee

        require(patient[patient_address].approved_trustees[msg.sender].active);
        return patient[patient_address].approved_trustees[msg.sender].document_link;
        
    }

    function addPatient(address patient_address) public onlyAdmin {
        // Here you can add an eligible patient address
        require(patient[patient_address].active == false);
        
        patient[patient_address].active = true;
        patient[patient_address].medinfo_position = 1;
    }

    function addDoctor(address doctor_address) public onlyAdmin {
        // Add an approved doctor address

        doctor[doctor_address].active = true;

    }

    function addPharmacy(address pharmacy_address) public onlyAdmin {
        // Add an approved pharmacy address

        pharmacy[pharmacy_address] = true;

    }

    function removeDoctor(address doctor_address) public onlyAdmin {
        // Remove a doctors address from approved addresses

        doctor[doctor_address].active = false;

    }

    function removePharmacy(address pharmacy_address) public onlyAdmin {
        // Remove a pharmacy address from approved addresses

        pharmacy[pharmacy_address] = false;

    }
    
    function approveTrustee(address trustee_address) public onlyPatient {
        // Add an approved trustee address
        
        require(msg.sender != trustee_address);
        patient[msg.sender].approved_trustees[trustee_address].active = true;

    }

    function revokeTrustee(address trustee_address) public onlyPatient {
        // remove an approved trustee address

        patient[msg.sender].approved_trustees[trustee_address].document_link = '';
        patient[msg.sender].approved_trustees[trustee_address].active = false;

    }

    function approveDoctor(address patient_address, address doctor_address) public onlyBefore(block.timestamp, msg.sender) {
        // Temporary approve an approved doctor address

        require((patient[msg.sender].active && patient_address == msg.sender) || patient[patient_address].approved_trustees[msg.sender].active);
        require(doctor[doctor_address].active);
        require((patient_address != doctor_address) && (msg.sender != doctor_address));
        patient[patient_address].approved_doctors[doctor_address] = true;

    }

    function revokeDoctor(address patient_address, address doctor_address) public {
        // remove an approved doctors address

        require((patient[msg.sender].active && patient_address == msg.sender) || patient[patient_address].approved_trustees[doctor_address].active);
        patient[patient_address].approved_doctors[doctor_address] = false;

    }

    function checkApprovedTrustee(address trustee_address) public view returns(bool i){
        // See if a trustee is approved in the contract

        return patient[msg.sender].approved_trustees[trustee_address].active;
    }

    function checkApprovedDoctor(address doctor_address, address patient_address) public view returns(bool){
        // A temp function to check if a doctor address is approved

        return patient[patient_address].approved_doctors[doctor_address];
    }

    function checkPatient(address patient_address) public view returns(bool){
        // Check a patient address state

        return patient[patient_address].active;
    }

    function setPublicKey(string memory _public_key) public {
        public_key[msg.sender] = _public_key;
    }

    function getPublicKey(address _address) public view returns(string memory){
        return public_key[_address];
    }

}
