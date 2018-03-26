<?php

$config = [
	"Hostname" => "houdi.ni",									// external hostname
	"External" => "http://play.houdi.ni/",						// external path to play
	"SecretKey" => "6LfEnEcUAAAAACzGi3GqTtYI0aFfwN_qACSmi10B", 	// reCaptcha secret key, leave blank to disable
	"Cloudflare" => false, 										// is host behind cloudflare?
	"Activate" => true, 										// activate user by default or send verification email
	"Clean" => true, 											// delete old inactive accounts?
	"CleanDays" => 10, 											// number of days before inactive accounts expire
	"ForceCase" => true,										// force CamelCase on usernames
	"AllowedChars" => "A-Za-z0-9)(*&^$!`\_+={};:@~#>.<",		// Allowed characters in usernames
	"Database" => [
		"Host" => "127.0.0.1", 									// mysql host
		"User" => "root", 										// mysql user
		"Pass" => "", 											// mysql password
		"Name" => "houdoo" 										// database name
	]
];

final class Database extends PDO {

	private $connection = null;

	public function __construct($host, $user, $password, $database) {
		$connectionString = sprintf("mysql:dbname=%s;host=%s", $database, $host);

		parent::__construct($connectionString, $user, $password);
	}
	
	public function encryptPassword($password, $md5 = true) {
		if($md5 !== false) {
			$password = md5($password);
		}
		$hash = substr($password, 16, 16) . substr($password, 0, 16);
		return $hash;
	}

	public function getLoginHash($password, $staticKey) {
		$hash = $this->encryptPassword($password, false);
		$hash .= $staticKey;
		$hash .= 'Y(02.>\'H}t":E1';
		$hash = $this->encryptPassword($hash);
		return $hash;
	}

	public function addUser($username, $password, $color, $email, $isActive = 0) {
		$hashedPassword = strtoupper(md5($password));
		$staticKey = 'houdini';
        $flashClientHash = $this->getLoginHash($hashedPassword, $staticKey);
        $bcryptPassword = password_hash($flashClientHash, PASSWORD_DEFAULT, [ 'cost' => 12 ]);
		$insertPenguin = "INSERT INTO `penguin` (`ID`, `Username`, `Nickname`, `Password`, `Email`, `Active`,  `Color`) VALUES ";
		$insertPenguin .= "(NULL, :Username, :Username, :Password, :Email, :Active, :Color);";
		
		$insertStatement = $this->prepare($insertPenguin);
		$insertStatement->bindValue(":Username", $username);
		$insertStatement->bindValue(":Password", $bcryptPassword);
		$insertStatement->bindValue(":Email", $email);
		$insertStatement->bindValue(":Active", $isActive);
		$insertStatement->bindValue(":Color", $color);
		
		$insertStatement->execute();
		$insertStatement->closeCursor();
		
		$penguinId = $this->lastInsertId();
		
		$this->insertInventory($penguinId, $color);
		$this->addActiveIgloo($penguinId);
		$this->sendMail($penguinId, null, 125);

		return $penguinId;
	}

	public function insertInventory($penguinId, $itemId) {
		$insertInventory = $this->prepare("INSERT INTO `inventory` (`PenguinID`, `ItemID`) VALUES (:PenguinID, :ItemID);");
		$insertInventory->bindValue(":PenguinID", $penguinId);
		$insertInventory->bindValue(":ItemID", $itemId);
		$insertInventory->execute();
		$insertInventory->closeCursor();
	}
	
	public function sendMail($recipientId, $senderId, $postcardType) {
		$sendMail = $this->prepare("INSERT INTO `postcard` (`ID`, `SenderID`, `RecipientID`, `Type`) VALUES (NULL, :SenderID, :RecipientID, :Type);");
		$sendMail->bindValue(":RecipientID", $recipientId);
		$sendMail->bindValue(":SenderID", $senderId);
		$sendMail->bindValue(":Type", $postcardType);
		$sendMail->execute();
		$sendMail->closeCursor();

		$postcardId = $this->lastInsertId();

		return $postcardId;
	}
    
	private function addActiveIgloo($penguinId) {
		$insertStatement = $this->prepare("INSERT INTO `igloo` (`ID`, `PenguinID`) VALUES (NULL, :PenguinID);");
		$insertStatement->bindValue(":PenguinID", $penguinId);
		$insertStatement->execute();
		$insertStatement->closeCursor();
		
		$iglooId = $this->lastInsertId();
		return $iglooId;
	}
	
	public function usernameTaken($username) {
		$usernameTaken = "SELECT Username FROM `penguins` WHERE Username = :Username;";
		
		$takenQuery = $this->prepare($usernameTaken);
		$takenQuery->bindValue(":Username", $username);
		$takenQuery->execute();
		
		$rowCount = $takenQuery->rowCount();
		$takenQuery->closeCursor();
		
		return $rowCount > 0;
	}

	public function createActivationKey($penguinId, $key) {
		$insertStatement = $this->prepare("INSERT INTO `activation_key` (`PenguinID`, `ActivationKey`) VALUES (:PenguinID, :Key);");
		$insertStatement->bindValue(":PenguinID", $penguinId);
		$insertStatement->bindValue(":Key", $key);
		$insertStatement->execute();
		$insertStatement->closeCursor();
	}

	public function activateUser($key) {
		$setActive = $this->prepare("UPDATE `penguin` INNER JOIN activation on penguins.ID = activation.PenguinID " . 
			"SET penguins.Active = 1 WHERE activation.Key = :Key;");
		$setActive->bindValue(":Key", $key);
		$setActive->execute();
		$deleteActivation = $this->prepare("DELETE FROM `activation` WHERE `Key` = :Key;");
		$deleteActivation->bindValue(":Key", $key);
		$deleteActivation->execute();
	}
	
	public function takenUsernames($username) {
		$usernamesTaken = "SELECT Username FROM `penguin` WHERE Username LIKE :Username;";
		
		$usernamesQuery = $this->prepare($usernamesTaken);
		$usernamesQuery->bindValue(":Username", $username . "%");
		$usernamesQuery->execute();
		
		$usernames = $usernamesQuery->fetchAll(self::FETCH_COLUMN);
		return $usernames;
	}

	public function cleanInactive($expiry = 10) {
		$deleteInactive = "DELETE FROM `penguin` WHERE Active = 0 AND RegistrationDate < :Expiry;";

		$deleteQuery = $this->prepare($deleteInactive);
		$deleteQuery->bindValue(":Expiry", time() - strtotime("$expiry days", 0));
		$deleteQuery->execute();
	}

}

$localization = [
	"en" => [
		"terms" => "You must agree to the Rules and Terms of Use.",
		"name_missing" => "You need to name your penguin.",
		"name_short" => "Penguin name is too short.",
		"name_number" => "Penguin names can only contain 5 numbers.",
		"penguin_letter" => "Penguin names must contain at least 1 letter.",
		"name_not_allowed" => "That penguin name is not allowed.",
		"name_taken" => "That penguin name is already taken.",
		"name_suggest" => "That penguin name is already taken. Try {suggestion}.",
		"passwords_match" => "Passwords do not match.",
		"password_short" => "Password is too short.",
		"email_invalid" => "Invalid email address."
	],
	"fr" => [
        "terms" => "Tu dois accepter les conditions d'utilisation.",
        "name_missing" => "Tu dois donner un nom à ton pingouin.",
        "name_short" => "Le nom de pingouin est trop court.",
        "name_number" => "Un nom de pingouin ne peut contenir plus de 5 nombres.",
        "penguin_letter" => "Un nom de pingouin doit contenir au moins une lettre.",
        "name_not_allowed" => "Ce nom de pingouing n'est pas autorisé.",
        "name_taken" => "Ce nom de pingouin est pris.",
        "name_suggest" => "Ce nom de pingouin est pris. Essaye {suggestion}.",
        "passwords_match" => "Les mots de passes ne correspondent pas.",
        "password_short" => "Le mot de passe est trop court.",
        "email_invalid" => "Adresse email invalide."
    ],
	"es" => [
		"terms" => "Debes seguir las reglas y los términos de uso.",
		"name_missing" => "Debes escoger un nombre para tu pingüino.",
		"name_short" => "El nombre de tu pingüino es muy corto.",
		"name_number" => "Los nombres de usuario sólo pueden tener 5 números.",
		"penguin_letter" => "Los nombres de usuario deben tener por lo menos 1 letra.",
		"name_not_allowed" => "Ese nombre de usuario no está permitido.",
		"name_taken" => "Ese nombre de usuario ya ha sido escogido.",
		"name_suggest" => "Ese nombre de usuario ya ha sido escogido. Intenta éste {suggestion}.",
		"passwords_match" => "Las contraseñas no coinciden.",
		"password_short" => "La contraseña es muy corta.",
		"email_invalid" => "El correo eléctronico es incorrecto."
	],
	"pt" => [
        "terms" => "Você precisa concordar com as Regras e com os Termos de Uso.",
        "name_missing" => "Voce precisa nomear seu pinguim.",
        "name_short" => "O nome do pinguim é muito curto.",
        "name_number" => "O nome do pinguim só pode conter 5 números",
        "penguin_letter" => "O nome do seu pinguim tem de conter pelomenos uma letra.",
        "name_not_allowed" => "Esse nome de pinguim não é permitido.",
        "name_taken" => "Esse nome de pinguim já foi escolhido.",
        "name_suggest" => "Esse nome de pinguim já foi escolhido. Tente {suggestion}.",
        "passwords_match" => "As senhas não estão iguais.",
        "password_short" => "A senha é muito curta.",
        "email_invalid" => "Esse endereço de E-Mail é invalido."
    ]
];

session_start();

function response($data) {
	die(http_build_query($data));
}

function attemptDataRetrieval($key, $session = false) {
	if(!$session && array_key_exists($key, $_POST)) {
		return $_POST[$key];
	}
    
    if($session && array_key_exists($key, $_SESSION)) {
        return $_SESSION[$key];
    }

	response([
		"error" => ""
	]);
}

function generateActivationKey($length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
{
    $str = '';
    $max = mb_strlen($keyspace, '8bit') - 1;
    for ($i = 0; $i < $length; ++$i) {
        $str .= $keyspace[random_int(0, $max)];
    }
    return $str;
}

$action = attemptDataRetrieval("action");
$lang = attemptDataRetrieval("lang");

if(!in_array($lang, array_keys($localization))) {
	response([
		"error" => ""
	]);
}

if($action == "validate_agreement") {
	$agreeTerms = attemptDataRetrieval("agree_to_terms");
	$agreeRules = attemptDataRetrieval("agree_to_rules");
	if(!$agreeTerms || !$agreeRules) {
		response([
			"error" => $localization[$lang]["terms"]
		]);
	}
	
	response([
		"success" => 1
	]);
} elseif($action == "validate_username") {
	$username = attemptDataRetrieval("username");
	$color = attemptDataRetrieval("colour");
	$colors = range(1, 15);
	
	if(strlen($username) == 0) {
		response([
			"error" => $localization[$lang]["name_missing"]
		]);
	} elseif(strlen($username) < 4 || strlen($username) > 12) {
		response([
			"error" => $localization[$lang]["name_short"]
		]);
	} elseif(preg_match_all("/[0-9]/", $username) > 5) {
		response([
			"error" => $localization[$lang]["name_number"]
		]);
	} elseif(!preg_match("/[A-z]/i", $username)) {
		response([
			"error" => $localization[$lang]["penguin_letter"]
		]);
    } elseif(preg_match("/[^" . $config["AllowedChars"] . "]/", $username)) {
		response([
			"error" => $localization[$lang]["name_not_allowed"]
		]);
    } elseif(!is_numeric($color) || !in_array($color, $colors)) {
		response([
			"error" => ""
		]);
	}
	
	$db = new Database($config["Database"]["Host"], $config["Database"]["User"], 
		$config["Database"]["Pass"], $config["Database"]["Name"]);

	if($db->usernameTaken($username)) {
		$username = preg_replace("/\d+$/", "", $username);
		$takenUsernames = $db->takenUsernames($username);
		$i = 1;
		while(true) {
			$suggestion = $username . $i++;
			if(preg_match_all("/[0-9]/", $username) > 1) {
				response([
					"error" => $localization[$lang]["name_taken"]
				]);
			}
			if(!in_array(strtolower($suggestion), $takenUsernames)) {
				break;
			}
		}
		response([
			"error" => str_replace("{suggestion}", $suggestion, $localization[$lang]["name_suggest"])
		]);
	}
	
	$_SESSION['sid'] = session_id();
	$_SESSION['username'] = ($config["ForceCase"] ? ucfirst(strtolower($username)) : $username);
	$_SESSION['colour'] = $color;
	
	response([
		"success" => 1,
		"sid" => session_id()
	]);
} elseif($action == "validate_password_email") {
	$sessionId = attemptDataRetrieval("sid", true);
	$username = attemptDataRetrieval("username", true);
	$color = attemptDataRetrieval("colour", true);
	$password = attemptDataRetrieval("password");
	$passwordConfirm = attemptDataRetrieval("password_confirm");
	$email = attemptDataRetrieval("email");
	$gtoken = attemptDataRetrieval("gtoken");

	if(!empty($config["SecretKey"])) {
		$post_data = http_build_query(
			[
				'secret' => $config["SecretKey"],
				'response' => $gtoken,
				'remoteip' => ($config["Cloudflare"] ? $_SERVER["HTTP_CF_CONNECTING_IP"] : $_SERVER['REMOTE_ADDR'])
			]
		);
		$opts = ['http' => [
			'method'  => 'POST',
			'header'  => 'Content-type: application/x-www-form-urlencoded',
			'content' => $post_data
		]];

		$context  = stream_context_create($opts);
		$response = file_get_contents('https://www.google.com/recaptcha/api/siteverify', false, $context);
		$result = json_decode($response);
	}

	if($sessionId !== session_id()) {
		response([
			"error" => ""
		]);
	} elseif(empty($result->success) && !empty($config["SecretKey"])) {
		response([
			"error" => ""
		]);
	} elseif($password !== $passwordConfirm) {
		response([
			"error" => $localization[$lang]["passwords_match"]
		]);
	} elseif(strlen($password) < 4) {
		response([
			"error" => $localization[$lang]["password_short"]
		]);
	} elseif(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		response([
			"error" => $localization[$lang]["email_invalid"]
		]);
	}
	
	$db = new Database($config["Database"]["Host"], $config["Database"]["User"], 
		$config["Database"]["Pass"], $config["Database"]["Name"]);
	$penguinId = $db->addUser($username, $password, $color, $email, ($config["Activate"] ? 1 : 0));

	if(!$config["Activate"]) {
		$db->createActivationKey($penguinId, generateActivationKey(60));

		$headers = "From: noreply@{$config['Hostname']}\r\n";
		$headers .= "Reply-To: noreply@{$config['Hostname']}\r\n";
		$headers .= "Return-Path: noreply@{$config['Hostname']}\r\n";

		ob_start();
?>

<!doctype html>
<html>
  <head>
    <title>Activate your penguin!</title>
  </head>
  <body>
    <p>Hello,</p>
    <p>Thank you for creating a penguin on <?php print($activationLink); ?>. Please click below to activate your penguin account.</p>
    <a href="<?php print($activationLink); ?>">Activate</a>
  </body>
</html>

<?php 
		$emailContent = ob_get_clean();

		mail($email, "Activate your penguin!", $emailContent, $headers);
	}

	if($config["Clean"] == true) {
		$db->cleanInactive($config["CleanDays"]);
	}
	
	session_destroy();
	
	response([
		"success" => 1
	]);
}

?>