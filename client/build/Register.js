import React, { useState , useEffect} from "react";
import Axios from "axios";
import {Link, useNavigate} from 'react-router-dom';
import Toast from 'react-bootstrap/Toast'
import {Row, Form, Button, Col, Image} from 'react-bootstrap';
import {Helmet} from 'react-helmet';
import GeneralNavbar from '../components/GeneralNavbar';
import GoogleButton from 'react-google-button';

////Register page of our website
//// registerUsername is the entered username by the user
//// registerPassword is the entered password by the user

//// authMsg is the flash message which may be show if 
//// user enters a used username or empty username or empty password

const Register = (props) => {
    const [registerUsername, setRegisterUsername] = useState("");
  	const [registerPassword, setRegisterPassword] = useState("");
  	const [registerEmail, setRegisterEmail] = useState("");
	const [usernameTooltipMessage, setUsernameTooltipMessage] = useState("Username can't be empty");
	const [emailTooltipMessage, setEmailTooltipMessage] = useState("Email can't be empty");
  	const [authMsg, setAuthMsg] = useState("");
	const [validUsername, setValidUsername] = useState(false);
	const [validEmail, setValidEmail] = useState(false);
  	const [showAuthMsg, setShowAuthMsg] = useState(false);
	const [showPassword, setShowPassword]=useState(false);
	const navigate = useNavigate();

	const handleShowPassword = () =>{
		setShowPassword(!showPassword);
	}

	////function to register user from the server after he has entered the information
    //// if all the information is valid redirect him to login page else display the flash message
  	const register = () => {
	    Axios({
			method: "POST",
			data: {
			username: registerUsername,
			email: registerEmail,
			password: registerPassword,
			role: "basic"
			},
			withCredentials: true,
			url: "/server/register",
      	}).then(function (response) {
        	setAuthMsg(response.data.message);
        	setShowAuthMsg(true);
        	if (response.data.redirect == '/') {
            	navigate(`/`);
        	} 
			else if(response.data.redirect == '/login') {
				navigate(`/auth/login`);
			}
     	});
  	};
   
	const registerWithGoogle = () => {
        // Axios does not work with Google Auth2.0 , need to navigate to the url directly
        window.open("https://tryfingo.com/auth/login-google", "_self");
    };

  	////when a user requests for the register , we check if he is already logged in
    ////If user is already logged in redirect him to home page else
    ////send the register page to let him register
  	useEffect ( () => {
    	Axios({
      		method: "GET",
      		withCredentials: true,
      		url: "/server/register",
      	}).then(function (response) {
			setAuthMsg(response.data.message);
        	setShowAuthMsg(true);
        	if (response.data.redirect == '/home') {
            	navigate(`/home`);
        	} 
     	}); 

  	}, []);

	const handleUsernameChange = (e) => {
		setRegisterUsername(e.target.value)
		var emailRegex = /\s/;
		if(e.target.value === ''){
			setUsernameTooltipMessage("Username can't be empty");
			setValidUsername(false);
		}
		else if(!emailRegex.test(e.target.value)){
			setUsernameTooltipMessage('');
			setValidUsername(true);
		}else{
			setUsernameTooltipMessage('Spaces are not allowed');
			setValidUsername(false);
		}
	};

	const handleEmailChange = (e) => {
		setRegisterEmail(e.target.value)
		var emailRegex = /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/;
		if(e.target.value === ''){
			setEmailTooltipMessage("Email can't be empty");
			setValidEmail(false);
		}
		else if(emailRegex.test(e.target.value)){
			setEmailTooltipMessage('Email valid');
			setValidEmail(true);
		}else{
			setEmailTooltipMessage('Email invalid');
			setValidEmail(false);
		}
	}

  	return (
    <>
	<Helmet><title>Register</title></Helmet>
	<GeneralNavbar/>
	<Row style={{ margin: "auto", width: "100%"}}>
        <Col style={{ marginTop: "100px" }}>
        	<div>
				<Form style={{ width: "40%", marginLeft: "30%", marginRight: "30%" }}>
            		<h1 style={{ textAlign: "center", marginBottom: "20px" }}>Register</h1>
            		<Toast onClose={() => setShowAuthMsg(false)} show={showAuthMsg} delay={2000} autohide>
          
              			<Toast.Body>{authMsg}</Toast.Body>
            		</Toast>
					
					<Form.Group >
						{/* <Form.Label>Enter a unique username</Form.Label> */}
						<Form.Text style={{ color: validUsername? 'green':'red' }}>
							{usernameTooltipMessage}
						</Form.Text>
						<Form.Control type="username" placeholder="Enter a unique username" 
						onChange={ handleUsernameChange} style={{ borderRadius: "10px", padding: "25px"}}/>
					</Form.Group>
					<br/>
					<Form.Group >
                    	{/* <Form.Label>Enter your email</Form.Label> */}
						<Form.Text style={{ color: validEmail? 'green':'red' }}>
							{emailTooltipMessage}
						</Form.Text>
                    	<Form.Control type="email" placeholder="Enter your email" 
						onChange={handleEmailChange} style={{ borderRadius: "10px", padding: "25px"}}/>
                	</Form.Group>
					<br/>
                	<Form.Group >
	                    {/* <Form.Label>Enter your password</Form.Label> */}
                    	<Form.Control type={showPassword?"text":"password"} placeholder="Enter your password"  
						onChange={(e) => setRegisterPassword(e.target.value)} style={{ borderRadius: "10px", padding: "25px", marginBottom: "10px"}}/>
                	</Form.Group>
					<Form.Group controlId="formBasicCheckbox">
	 					<Form.Check type="checkbox" label="Show Password" onClick={handleShowPassword} />
  					</Form.Group>
					<br/>
                	<Button style={{ borderRadius: "10px", padding: "13px", width: "100%"}} variant={(validUsername && validEmail)? 'success':'danger'} disabled = {!(validUsername && validEmail)} onClick={register}>Submit</Button>
                	<br />
                	<br />
					<GoogleButton style={{ width: "100%"}}  onClick={registerWithGoogle}/>
					<br/>
                	<div style={{ textAlign: "center", marginBottom: "20px" }}>Already have an account? Login Now...</div>
                	<Link to="/auth/login"><Button style={{ textAlign: "center", width: "100%", padding: "10px", borderRadius: "10px"}}>Login</Button></Link>
            	</Form>
        	</div>
        </Col>
    </Row>
    </>
  );
}
 
export default Register;