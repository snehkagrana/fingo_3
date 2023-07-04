import React, { useState , useEffect} from "react";
import Axios from "axios";
import {Link, useNavigate } from 'react-router-dom';
import Form from 'react-bootstrap/Form'
import Button from 'react-bootstrap/Button'
import {Row,  Col, Image} from 'react-bootstrap';
import {Helmet} from 'react-helmet';
import GeneralNavbar from '../components/GeneralNavbar';
const logo = require('../teach.png');

////This is the home page of the website, which is user directed to the
////after he has been authenticated, where he is given 2 options whether
////to join an existing room or create a new one

////data represents username of the logged in username
////join room is the invitation link to which user must be redirected to
const StartPage = (props) => {
	const navigate = useNavigate();

	////to authenticate user before allowing him to enter the home page
	////if he is not redirect him to login page
	useEffect ( () => {
		// console.log("in use effect");
		Axios({
			method: "GET",
			withCredentials: true,
			url: "/server/login",
		}).then(function (response) {
			if (response.data.redirect != '/login') {
				// console.log("Already logged in");
                navigate(`/home`);
			}
		}); 
	}, []);

	return (
		<>
		<Helmet><title>Fingo - Learn Finance the Fun Way</title></Helmet>
		<GeneralNavbar/>
		<br/>
		<br/>

		<Row style={{ margin: 'auto', width: '80%' }}>
      <Col xs={12} md={6} style={{ marginTop: '10%' }}>
        <img
          src={logo}
          className="img-fluid"
          alt="Learn Finance Logo"
        />
      </Col>
      <Col xs={12} md={6} style={{ marginTop: '10%' }}>
        <h1>
          <span style={{ fontWeight: 'bold' }}>Learn Finance the Fun Way!</span>
        </h1>
        <br />
        <h5>
          Get access to 450+ chapters on Investing, Trading, Crypto, and more.
          Each only 3 minutes long.
        </h5>
        <br />
        <h5>Plus, challenge yourself with 1800+ quizzes to test your knowledge.</h5>
        <br />
        <Button
          style={{
            width: '50%',
            marginLeft: '25%',
            padding: '15px',
            borderRadius: '15px',
            boxShadow: 'initial',
          }}
          onClick={() => navigate('/auth/login')}
        >
          Get Started
        </Button>
      </Col>
    </Row>

		{/* <Row style={{ margin: "auto", width: "80%"}}>
			<Col> 
				<img 
					src={logo} 
					height={500}
					width={600}
					fluid 
					alt="Learn Finance Logo" 
				/>
			</Col>
			<Col style={{ marginTop: "10%"}}>
				<h1><span style={{fontWeight: 'bold'}}>Learn Finance the Fun Way!</span></h1>
				<br/>
				<h5 > Get access to 450+ chapters on Investing, Trading, Crypto, and more. Each only 3 minutes long.</h5>
				<br/>
				<h5>Plus, challenge yourself with 1800+ quizzes to test your knowledge.</h5>
				<br/>
			<Button style={{ width: "50%", marginLeft: "25%", padding: "15px", borderRadius: "15px", boxShadow: "initial" }} onClick={() => navigate(`/auth/login`)}>Get Started</Button> 
			</Col>
		</Row> */}
		</>
	);
};

export default StartPage; 