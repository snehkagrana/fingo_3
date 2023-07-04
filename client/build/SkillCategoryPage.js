import React, { useRef, useState , useEffect} from "react";
import {useParams} from 'react-router-dom';
import Axios from "axios";
import {Link, useNavigate } from 'react-router-dom';
import {Badge, Card, Button, Col, Image} from 'react-bootstrap';
import {Helmet} from 'react-helmet';
import Navbar from '../components/Navbar';

const SkillCategoryPage = () => {
    const {skillName} = useParams();
    const {categoryName} = useParams();
    const navigate = useNavigate();
	const role = useRef('');
	const [categories, setCategories] = useState([]);
	const [subCategories, setSubCategories] = useState([]);
	const checkIsCompleted = useRef([]);

	const getSkillBySkillName = () => {
		Axios({
			method: "GET",
			withCredentials: true,
			url: `/server/skills/${skillName}`,
		}).then((res) => {
			// console.log("skill name", skillName);
			// console.log("skill is ", res.data.data[0]);
			// categories.current = res.data.data[0].categories;
			// console.log("categories - ", categories.current);
			setCategories(res.data.data[0].categories);
            var subCategoriesList = (res.data.data[0].sub_categories).filter(function (el)
    			{	return el.category === categoryName;});
			// console.log('filtered sub categories', subCategoriesList);
            setSubCategories(subCategoriesList);
		});
	};

	const handleSubCategorySelection=(sub_category)=>{ 
        // console.log("handleSubCategorySelection",sub_category);
		navigate(`/skills/${skillName}/${categoryName}/${sub_category}/information/${0}`);
    }

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
				role.current = response.data.user.role;
				var tempCheckIsCompleted = [];
				response.data.user.score.forEach((score) => {
					if(score.skill === skillName && score.category === categoryName)
					tempCheckIsCompleted = tempCheckIsCompleted.concat(score.sub_category);
				});
				checkIsCompleted.current = tempCheckIsCompleted;
				// console.log('checkIsCompleted', checkIsCompleted.current);
			}
		}); 
		
	}, []);

    return ( 
        <>
		<Helmet><title>{skillName.split("_").join(" ")} {'->'} {categoryName.split("_").join(" ")}</title></Helmet>
		<Navbar  proprole={role}/>
        <div className="skill-page">
			<br/>
			<h2 className="text-center"><Badge pill bg="light">{skillName.split("_").join(" ")} {'->'} {categoryName.split("_").join(" ")}</Badge></h2>
			
			{(subCategories)? ((subCategories).map((sub_category, i) =>
            <>
			<br/>
			<div key={i}>
			<Card >
				<Card.Header as="h5" >{sub_category.sub_category.split("_").join(" ")}{' '}{checkIsCompleted.current.includes(sub_category.sub_category)? <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check-circle-fill" viewBox="0 0 16 16">
  <path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zm-3.97-3.03a.75.75 0 0 0-1.08.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-.01-1.05z"/>
</svg> : null}</Card.Header>
				<Card.Body>
					{/* <Card.Title>{category}</Card.Title> */}
					{/* <Card.Text>
					With supporting text below as a natural lead-in to additional content.
					</Card.Text> */}
					<Button onClick={() => handleSubCategorySelection(sub_category.sub_category)}>Let's Go</Button> 
				</Card.Body>
			</Card>
			</div>
			</>
            )):null}
           
		   <br></br>
        </div>
		
        </>
     );
}
 
export default SkillCategoryPage;

/**
 * var checkIsCompleted = response.data.user.score.filter(function (score){
					return (score.skill === skillName && score.category === category && score.sub_category === subcategory);
				})
 */