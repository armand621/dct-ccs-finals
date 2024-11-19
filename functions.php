<?php    
    // All project functions should be placed here

session_start();    
function postData($key){
    return $_POST["$key"];
}

function guardLogin(){
    
    $dashboardPage = 'admin/dashboard.php';

    if(isset($_SESSION['email'])){
        header("Location: $dashboardPage");
    } 
}

function guardDashboard(){
    $loginPage = '../index.php';
    if(!isset($_SESSION['email'])){
        header("Location: $loginPage");
    }
}

 
function getConnection() {
    // Database configuration
    $host = 'localhost'; // Replace with your host
    $dbName = 'dct-ccs-finals'; // Replace with your database name
    $username = 'root'; // Replace with your username
    $password = 'root'; // Replace with your password
    $charset = 'utf8mb4'; // Recommended for UTF-8 support
    
    try {
        $dsn = "mysql:host=$host;dbname=$dbName;charset=$charset";
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        return new PDO($dsn, $username, $password, $options);
    } catch (PDOException $e) {
        die("Connection failed: " . $e->getMessage());
    }
}

function login($email, $password) {
    $validateLogin = validateLoginCredentials($email, $password);

    if(count($validateLogin) > 0){
        echo displayErrors($validateLogin);
        return;
    }


    // Get database connection
    $conn = getConnection();

    // Convert the input password to MD5
    $hashedPassword = md5($password);

    // SQL query to check if the email and hashed password match
    $query = "SELECT * FROM users WHERE email = :email AND password = :password";
    $stmt = $conn->prepare($query);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password', $hashedPassword);
    
    $stmt->execute();
    
    // Fetch the user data if found
    $user = $stmt->fetch();

    if ($user) {
        // Login successful
        // return $user;
        $_SESSION['email'] = $user['email'];
        header("Location: admin/dashboard.php");
    } else {
        // Login failed
        echo displayErrors(["Invalid email or password"]);
    }
}



function validateLoginCredentials($email, $password) {
    $errors = [];
    
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }
    
    if (empty($password)) {
        $errors[] = "Password is required.";
    }
    
    return $errors;
}



function displayErrors($errors) {
    if (empty($errors)) return "";

    $errorHtml = '<div class="alert alert-danger alert-dismissible fade show" role="alert"><strong>System Alerts</strong><ul>';

    // Make sure each error is a string
    foreach ($errors as $error) {
        // Check if $error is an array or not
        if (is_array($error)) {
            // If it's an array, convert it to a string (you could adjust this to fit your needs)
            $errorHtml .= '<li>' . implode(", ", $error) . '</li>';
        } else {
            $errorHtml .= '<li>' . htmlspecialchars($error) . '</li>';
        }
    }

    $errorHtml .= '</ul><button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>';

    return $errorHtml;
}






function addSubject($subject_code, $subject_name) {
    $validateSubjectData = validateSubjectData($subject_code, $subject_name);

    $checkDuplicate = checkDuplicateSubjectData($subject_code, $subject_name);

    if(count($validateSubjectData) > 0 ){
        echo displayErrors($validateSubjectData);
        return;
    }

    if(count($checkDuplicate) == 1 ){
        echo displayErrors($checkDuplicate);
        return;
    }


    // Get database connection
    $conn = getConnection();

    try {
        // Prepare SQL query to insert subject into the database
        $sql = "INSERT INTO subjects (subject_code, subject_name) VALUES (:subject_code, :subject_name)";
        $stmt = $conn->prepare($sql);

        // Bind parameters to the SQL query
        $stmt->bindParam(':subject_code', $subject_code);
        $stmt->bindParam(':subject_name', $subject_name);

        // Execute the query
        if ($stmt->execute()) {
            return true; // Subject successfully added
        } else {
            return "Failed to add subject."; // Query execution failed
        }
    } catch (PDOException $e) {
        // Return error message if the query fails
        return "Error: " . $e->getMessage();
    }
}





function validateSubjectData($subject_code, $subject_name ) {
    $errors = [];

    // Check if subject_code is empty
    if (empty($subject_code)) {
        $errors[] = "Subject code is required.";
    }

    // Check if subject_name is empty
    if (empty($subject_name)) {
        $errors[] = "Subject name is required.";
    }

    return $errors;
}

// Function to check if the subject already exists in the database (duplicate check)
function checkDuplicateSubjectData($subject_code, $subject_name) {
    // Get database connection
    $conn = getConnection();

    // Query to check if the subject_code already exists in the database
    $sql = "SELECT * FROM subjects WHERE subject_code = :subject_code OR subject_name = :subject_name";
    $stmt = $conn->prepare($sql);

    // Bind parameters
    $stmt->bindParam(':subject_code', $subject_code);
    $stmt->bindParam(':subject_name', $subject_name);

    // Execute the query
    $stmt->execute();

    // Fetch the results
    $existing_subject = $stmt->fetch(PDO::FETCH_ASSOC);

    // If a subject exists with the same code or name, return an error
    if ($existing_subject) {
        return ["Duplicate subject found: The subject code or name already exists."];
    }

    return [];
}



// Function to check if the subject already exists in the database (duplicate check)
function checkDuplicateSubjectForEdit($subject_name) {
    // Get database connection
    $conn = getConnection();

    // Query to check if the subject_code already exists in the database
    $sql = "SELECT * FROM subjects WHERE subject_name = :subject_name";
    $stmt = $conn->prepare($sql);

    // Bind parameters
    $stmt->bindParam(':subject_name', $subject_name);

    // Execute the query
    $stmt->execute();

    // Fetch the results
    $existing_subject = $stmt->fetch(PDO::FETCH_ASSOC);

    // If a subject exists with the same code or name, return an error
    if ($existing_subject) {
        return ["Duplicate subject found: The subject code or name already exists."];
    }

    return [];
}




function fetchSubjects() {
    // Get the database connection
    $conn = getConnection();

    try {
        // Prepare SQL query to fetch all subjects
        $sql = "SELECT * FROM subjects";
        $stmt = $conn->prepare($sql);

        // Execute the query
        $stmt->execute();

        // Fetch all subjects as an associative array
        $subjects = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Return the list of subjects
        return $subjects;
    } catch (PDOException $e) {
        // Return an empty array in case of error
        return [];
    }
}

function getSubjectByCode($subject_code) {
    $pdo = getConnection();
    $query = "SELECT * FROM subjects WHERE subject_code = :subject_code";
    $stmt = $pdo->prepare($query);
    $stmt->execute([':subject_code' => $subject_code]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}


function updateSubject($subject_code, $subject_name, $redirectPage) {

    $validateSubjectData = validateSubjectData($subject_code, $subject_name);

    $checkDuplicate = checkDuplicateSubjectForEdit($subject_name);

    if(count($validateSubjectData) > 0 ){
        echo displayErrors($validateSubjectData);
        return;
    }

    if(count($checkDuplicate) == 1 ){
        echo displayErrors($checkDuplicate);
        return;
    }


    try {
        // Get the database connection
        $pdo = getConnection();

        // Prepare the SQL query for updating the subject
        $sql = "UPDATE subjects SET subject_name = :subject_name WHERE subject_code = :subject_code";
        $stmt = $pdo->prepare($sql);

        // Bind the parameters
        $stmt->bindParam(':subject_name', $subject_name, PDO::PARAM_STR);
        $stmt->bindParam(':subject_code', $subject_code, PDO::PARAM_STR);

        // Execute the query
        if ($stmt->execute()) {
            echo "<script>window.location.href = '$redirectPage';</script>";
        } else {
            //echo displayErrors(["Failed to update subject!"]);
            return 'Failed to update subject';
        }
    } catch (PDOException $e) {
        // echo displayErrors(["Error: " . $e->getMessage()]);
        return "Error: " . $e->getMessage();
    }
}



function deleteSubject($subject_code, $redirectPage) {
    try {
        // Get the database connection
        $pdo = getConnection();

        // Prepare the SQL query to delete the subject
        $sql = "DELETE FROM subjects WHERE subject_code = :subject_code";
        $stmt = $pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':subject_code', $subject_code, PDO::PARAM_STR);

        // Execute the query
        if ($stmt->execute()) {
            echo "<script>window.location.href = '$redirectPage';</script>";
        } else {
            return "Failed to delete the subject with code $subject_code.";
        }
    } catch (PDOException $e) {
        return "Error: " . $e->getMessage();
    }
}






function fetchStudents() {
    // Get the database connection
    $conn = getConnection();

    try {
        // Prepare SQL query to fetch all subjects
        $sql = "SELECT * FROM students";
        $stmt = $conn->prepare($sql);

        // Execute the query
        $stmt->execute();

        // Fetch all subjects as an associative array
        $subjects = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Return the list of subjects
        return $subjects;
    } catch (PDOException $e) {
        // Return an empty array in case of error
        return [];
    }
}


function addStudent($student_id, $student_firstname, $student_lastname){

    $validateStudentData = validateStudentData($student_id, $student_firstname, $student_lastname);
    $checkDuplicateStudentData = checkDuplicateStudentData($student_id);

    if(count($validateStudentData) > 0){
        echo displayErrors($validateStudentData);
        return;
    }

    if(count($checkDuplicateStudentData) == 1){
        echo displayErrors($checkDuplicateStudentData);
        return;
    }


    $conn = getConnection();

    try {
        // Prepare SQL query to insert subject into the database
        $sql = "INSERT INTO students (student_id, first_name, last_name) VALUES (:student_id, :first_name, :last_name)";
        $stmt = $conn->prepare($sql);

        // Bind parameters to the SQL query
        $stmt->bindParam(':student_id', $student_id);
        $stmt->bindParam(':first_name', $student_firstname);
        $stmt->bindParam(':last_name', $student_lastname);

        // Execute the query
        if ($stmt->execute()) {

            return true; // Student successfully added
        } else {
            return "Failed to add subject."; // Query execution failed
        }
    } catch (PDOException $e) {
        // Return error message if the query fails
        return "Error: " . $e->getMessage();
    }

}



function getStudentById($student_id) {
    $pdo = getConnection();
    $query = "SELECT * FROM students WHERE student_id = :student_id";
    $stmt = $pdo->prepare($query);
    $stmt->execute([':student_id' => $student_id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}




function updateStudent($student_id, $student_firstname, $student_lastname, $redirectPage){


    $validateStudentData = validateStudentData($student_id, $student_firstname, $student_lastname);
    //$checkDuplicateStudentData = checkDuplicateStudentForEdit($student_id);

    if(count($validateStudentData) > 0){
        echo displayErrors($validateStudentData);
        return;
    }

    // if(count($checkDuplicateStudentData) == 1){
    //     echo displayErrors($checkDuplicateStudentData);
    //     return;
    // }



    try {
        // Get the database connection
        $pdo = getConnection();

        // Prepare the SQL query for updating the subject
        $sql = "UPDATE students SET first_name = :firstname, last_name = :lastname  WHERE student_id = :student_id";
        $stmt = $pdo->prepare($sql);

        // Bind the parameters
        $stmt->bindParam(':firstname', $student_firstname, PDO::PARAM_STR);
        $stmt->bindParam(':lastname', $student_lastname, PDO::PARAM_STR);
        $stmt->bindParam(':student_id', $student_id, PDO::PARAM_STR);

        // Execute the query
        if ($stmt->execute()) {
            echo "<script>window.location.href = '$redirectPage';</script>";
        } else {
            //echo displayErrors(["Failed to update subject!"]);
            return 'Failed to update subject';
        }
    } catch (PDOException $e) {
        // echo displayErrors(["Error: " . $e->getMessage()]);
        return "Error: " . $e->getMessage();
    }
}






//for adding student validation
function validateStudentData($student_id, $student_firstname, $student_lastname ) {
    $errors = [];

    // Check if subject_code is empty
    if (empty($student_id)) {
        $errors[] = "Student id is required.";
    }

    if (empty($student_firstname)) {
        $errors[] = "Student firstname is required.";
    }

    // Check if subject_name is empty
    if (empty($student_lastname)) {
        $errors[] = "Student lastname is required.";
    }

    return $errors;
}


function checkDuplicateStudentData($student_id) {
    // Get database connection
    $conn = getConnection();

    // Query to check if the subject_code already exists in the database
    $sql = "SELECT * FROM students WHERE student_id = :student_id";
    $stmt = $conn->prepare($sql);

    // Bind parameters
    $stmt->bindParam(':student_id', $student_id);
    
    // Execute the query
    $stmt->execute();

    // Fetch the results
    $existing_student = $stmt->fetch(PDO::FETCH_ASSOC);

    // If a subject exists with the same code or name, return an error
    if ($existing_student) {
        return ["Duplicate student id found: The student id already exists."];
    }

    return [];
}



function deleteStudent($student_id, $redirectPage) {
    try {
        // Get the database connection
        $pdo = getConnection();

        // Prepare the SQL query to delete the subject
        $sql = "DELETE FROM students WHERE student_id = :student_id";
        $stmt = $pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':student_id', $student_id, PDO::PARAM_STR);

        // Execute the query
        if ($stmt->execute()) {
            echo "<script>window.location.href = '$redirectPage';</script>";
        } else {
            return "Failed to delete the subject with code $student_id.";
        }
    } catch (PDOException $e) {
        return "Error: " . $e->getMessage();
    }
}





function getAllSubjectsCheckboxes($student_id) {
    // Get database connection
    $conn = getConnection(); 

    // SQL query to fetch all subjects that are not assigned to the student
    $sql = "SELECT subject_code, subject_name 
            FROM subjects 
            WHERE subject_code NOT IN (SELECT subject_id FROM students_subjects WHERE student_id = :student_id)";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':student_id', $student_id);
    $stmt->execute();

    // Fetch all subjects
    $subjects = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Generate the HTML for checkboxes
    $checkboxes = '';
    foreach ($subjects as $subject) {
        $checkboxes .= '<div class="form-check">';
        $checkboxes .= '<input class="form-check-input" type="checkbox" name="subjects[]" value="' . htmlspecialchars($subject['subject_code']) . '" id="subject_' . htmlspecialchars($subject['subject_code']) . '">';
        $checkboxes .= '<label class="form-check-label" for="subject_' . htmlspecialchars($subject['subject_code']) . '">';
        $checkboxes .= htmlspecialchars($subject['subject_code']) . ' - ' . htmlspecialchars($subject['subject_name']);
        $checkboxes .= '</label>';
        $checkboxes .= '</div>';
    }

    // Return the HTML checkboxes
    return $checkboxes;
}




function fetchAssignSubjects($student_id) {
    // Get the database connection
    $conn = getConnection();

    try {
        // Prepare SQL query to fetch all subjects
        $sql = "SELECT asign.subject_id, subs.subject_name, asign.grade FROM students_subjects asign JOIN subjects subs ON asign.subject_id = subs.subject_code";
        $stmt = $conn->prepare($sql);

        // Execute the query
        $stmt->execute();

        // Fetch all subjects as an associative array
        $subjects = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Return the list of subjects
        return $subjects;
    } catch (PDOException $e) {
        // Return an empty array in case of error
        return [];
    }
}



function assignSubjectsToStudent($student_id, $subject_codes) {
    $st_id = intval($student_id); // Ensure the student_id is an integer
    $numSubjectCodes = array();

    // Convert subject codes to integers
    for ($i = 0; $i < count($subject_codes); $i++) {
        $numSubjectCodes[$i] = intval($subject_codes[$i]);
    }

    try {
        // Get the database connection
        $conn = getConnection();

        // Loop through each subject_code
        for ($i = 0; $i < count($subject_codes); $i++) {
            // Check if the subject is already assigned to the student
            $sql_check = "SELECT COUNT(*) FROM students_subjects WHERE student_id = :student_id AND subject_id = :subject_id";
            $stmt_check = $conn->prepare($sql_check);

            // Bind parameters for the check query
            $stmt_check->bindParam(':student_id', $st_id, PDO::PARAM_INT);
            $stmt_check->bindParam(':subject_id', $numSubjectCodes[$i], PDO::PARAM_INT);
            $stmt_check->execute();

            // Fetch the result (count of matching records)
            $existing = $stmt_check->fetchColumn();

            // If the subject is not assigned already, proceed to insert
            if ($existing == 0) {
                $sql = "INSERT INTO students_subjects (student_id, subject_id, grade) 
                        VALUES (:student_id, :subject_id, 0.00)";
                $stmt = $conn->prepare($sql);

                // Bind parameters for the insert query
                $stmt->bindParam(':student_id', $st_id, PDO::PARAM_INT);
                $stmt->bindParam(':subject_id', $numSubjectCodes[$i], PDO::PARAM_INT);
                
                // Execute the query
                $stmt->execute();
            }
        }

        // Success message after all subjects are assigned
        echo "Subjects assigned successfully!";
    } catch (PDOException $e) {
        return "Error: " . $e->getMessage();
    }
}


function detachSubject($student_id, $subject_id, $redirectPage) {
    try {
        // Get the database connection
        $pdo = getConnection();

        // Prepare the SQL query to delete the subject
        $sql = "DELETE FROM students_subjects WHERE student_id = :student_id && subject_id = :subject_id";
        $stmt = $pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':student_id', $student_id, PDO::PARAM_STR);
        $stmt->bindParam(':subject_id', $subject_id, PDO::PARAM_STR);

        // Execute the query
        if ($stmt->execute()) {
            echo "<script>window.location.href = '$redirectPage';</script>";
        } else {
            return "Failed to delete the subject with code $student_id.";
        }
    } catch (PDOException $e) {
        return "Error: " . $e->getMessage();
    }
}

// function assignSubjectsToStudent($student_id, $subject_codes) {

//     $st_id = intval($student_id);
//     $numSubjectCodes = array();
//     for($i = 0; $i < count($subject_codes); $i++){
//         $numSubjectCodes[$i] = intval($subject_codes[$i]);
//     }


//     try {
//         // Get the database connection
//         $conn = getConnection();
    
//         // Loop through each subject_code and insert into the students_subjects table
//         for($i = 0; $i < count($subject_codes); $i++){
//             $sql = "INSERT INTO students_subjects (student_id, subject_id, grade) 
//                     VALUES (:student_id, :subject_id, 0.00)";
//             $stmt = $conn->prepare($sql);
    
//             // Bind parameters
//             $stmt->bindParam(':student_id', $st_id, PDO::PARAM_INT);
//             $stmt->bindParam(':subject_id', $numSubjectCodes[$i], PDO::PARAM_INT);    
//             // Execute the query
//             $stmt->execute();
//         }
    
//         echo "Subjects assigned successfully!";
//     } catch (PDOException $e) {
//         return "Error: " . $e->getMessage();
//     }
// }



function GETdata($key){
    return $_GET["$key"];
}


function isPost(){
    return $_SERVER['REQUEST_METHOD'] == "POST";
}



function logout($indexPage) {
    // Unset the 'email' session variable
    unset($_SESSION['email']);

    // Destroy the session
    session_destroy();

    // Redirect to the login page (index.php)
    header("Location: $indexPage");
    exit;
}





    
?>