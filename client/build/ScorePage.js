import React, { useRef, useState , useEffect} from "react";
import {useParams, useLocation} from 'react-router-dom';
import Axios from "axios";
import {Link, useNavigate } from 'react-router-dom';
import {Badge, Card, Button, Col, Image} from 'react-bootstrap';
import {Helmet} from 'react-helmet';
import Navbar from '../components/Navbar';

const ScorePage = (props) => {
    const {skillName, category, subcategory} =useParams();
    const location = useLocation();
    const navigate = useNavigate();
    const [skillDetails, setSkillDetails] = useState({});
	const role = useRef('');
	const allSubCategories = useRef([]);
	const totalSubCategories = useRef(-1);
	const subCategoryIndex = useRef(-1);

	// console.log('location', location);
    const data = location.state?.data;
    // console.log('data', data);
    // console.log('data score', data.score.current);
    // console.log('data points', data.points.current);

    var total_score = 0;
	const [points, setPoints] = useState(0);
    

	const getSkillBySkillName = () => {
		Axios({
			method: "GET",
			withCredentials: true,
			url: `/server/skills/${skillName}`,
		}).then((res) => {
			// console.log("skill is ", res.data.data);
			setSkillDetails(res.data.data[0]);
			allSubCategories.current = res.data.data[0].sub_categories.filter(function (sub_category){
				return sub_category.category === category;
			})
			// console.log('allSubCategories', allSubCategories.current);
			totalSubCategories.current = allSubCategories.current.length;
			for (var i = 0; i < totalSubCategories.current; i++){
				// console.log('allSubCategories.current[i].sub_category', allSubCategories.current[i].sub_category);
				// console.log('subcategory', subcategory);
				// console.log('(allSubCategories.current[i].sub_category === subcategory)', (allSubCategories.current[i].sub_category === subcategory));
				if(allSubCategories.current[i].sub_category === subcategory){
					subCategoryIndex.current = i;
					break;
				}
			}
			// console.log('totalSubCategories', totalSubCategories.current);
			// console.log('subCategoryIndex', subCategoryIndex.current);
		});
	};

	const getAllScores = () => {
		Axios({
			method: "GET",
			withCredentials: true,
			url: `/server/allscores`,
		}).then((res) => {
			// console.log("all scores ", res.data);
		});
	};

    ////to authenticate user before allowing him to enter the home page
	////if he is not redirect him to login page
	useEffect ( () => {
		// console.log("in use effect");
		Axios({
			method: "GET",
			withCredentials: true,
			url: "/server/login",
		}).then(function (response) {
			if (response.data.redirect == '/login') {
				// console.log("Please log in");
				navigate(`/auth/login`);
			} 
			else{
				// console.log("Already logged in");
				getSkillBySkillName();
				getAllScores();
				setPoints( data.points.current);
				role.current = response.data.user.role;
			}
		}); 
		
	}, []);

    return ( 
        <>
		<Helmet><title>Score page</title></Helmet>
		<Navbar  proprole={role}/>
        <div>
		<h2 className="text-center"><Badge pill bg="light">{skillName.split("_").join(" ")} {'->'} {category.split("_").join(" ")} {'->'} {subcategory.split("_").join(" ")}</Badge></h2>
		<br></br>
		{data? 
		<Card className="d-flex flex-column" style={{width: "80%", margin: "0 auto", borderRadius: '15px'}}>


			<Card.Header>Congratulations</Card.Header>
			<Card.Body>
				<Card.Text>You scored {points} points</Card.Text>
				<div style={{ display: "flex", justifyContent: "center", alignItems: "center" }} >
				{((subCategoryIndex.current) + 1 < (totalSubCategories.current)) &&
		<><Button  onClick={()=> { navigate(`/skills/${skillName}/${category}/${allSubCategories.current[(subCategoryIndex.current) + 1].sub_category}/information/${0}`)}}>Next: Start with {allSubCategories.current[(subCategoryIndex.current) + 1].sub_category.split("_").join(" ")}</Button>{' '}</>}
		{((subCategoryIndex.current) + 1 === (totalSubCategories.current)) &&
		<><Button  onClick={() => {navigate(`/skills/${skillName}/${category}`);}}>Go Back!!</Button>{' '}</>}</div>
			</Card.Body>
		</Card>
		:"Loading"}
			<br/><br/> 
		</div>
        </>
     );
}
 
export default ScorePage;