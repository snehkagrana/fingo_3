import React, { useState ,useRef, useEffect} from "react";
import {
  MDBContainer,
  MDBNavbar,
  MDBNavbarBrand,
  MDBNavbarToggler,
  MDBIcon,
  MDBNavbarNav,
  MDBNavbarItem,
  MDBNavbarLink,
  MDBCollapse,
} from 'mdb-react-ui-kit';
import {Link, useNavigate } from 'react-router-dom';


const GeneralNavbar = ({proprole}) => {

  

    const [showBasic, setShowBasic] = useState(false);
	const navigate = useNavigate();

  return (
    <MDBNavbar expand='lg' light bgColor='light'>
      <MDBContainer fluid>
        <MDBNavbarBrand onClick ={() => navigate(`/`)}><span style={{fontWeight: 'bold'}}>Fingo</span></MDBNavbarBrand>

        <MDBNavbarToggler
          aria-controls='navbarSupportedContent'
          aria-expanded='false'
          aria-label='Toggle navigation'
          onClick={() => setShowBasic(!showBasic)}
        >
          <MDBIcon icon='bars' fas />
        </MDBNavbarToggler>

        <MDBCollapse navbar show={showBasic}>
          <MDBNavbarNav className='mr-auto mb-2 mb-lg-0'>
            <MDBNavbarItem>
              <MDBNavbarLink onClick = {()=> navigate(`/`)}>Home</MDBNavbarLink>
            </MDBNavbarItem>        
            <MDBNavbarItem>
              <MDBNavbarLink onClick = {()=> navigate(`/auth/login`)}>Login</MDBNavbarLink>
            </MDBNavbarItem>        
            <MDBNavbarItem>
              <MDBNavbarLink onClick = {()=> navigate(`/auth/register`)}>Register</MDBNavbarLink>
            </MDBNavbarItem>                
            <MDBNavbarItem>
              <MDBNavbarLink onClick = {()=> navigate(`/contactus`)}>Contact Us</MDBNavbarLink>
            </MDBNavbarItem>
            <MDBNavbarItem>
              <MDBNavbarLink onClick = {()=> navigate(`/aboutus`)}>About Us</MDBNavbarLink>
            </MDBNavbarItem>
            <MDBNavbarItem>
              <MDBNavbarLink onClick = {()=> navigate(`/terms`)}>Terms</MDBNavbarLink>
            </MDBNavbarItem>
            <MDBNavbarItem>
              <MDBNavbarLink onClick = {()=> navigate(`/privacypolicy`)}>Privacy Policy</MDBNavbarLink>
            </MDBNavbarItem>
          </MDBNavbarNav>
        </MDBCollapse>
      </MDBContainer>
    </MDBNavbar>
  );
}; 

export default GeneralNavbar;