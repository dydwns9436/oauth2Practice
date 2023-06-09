import { useNavigate } from 'react-router-dom';
import {
  LoginContainer,
  LoginForm,
  LoginTitle,
  Input,
  LoginButton,
  // GoogleLoginButton,
  Error,
  FooterText,
  StyledLink,
  // GoogleLogo,
  LogoContainer,
  BackGround,
  StyledLogo,
  BackYellow,
} from '../style/LoginStyle';

import { useState } from 'react';
import { useDispatch } from 'react-redux';
import { login } from '../store/userSlice';
import jwt_decode from 'jwt-decode';
import axiosInstance from '../axiosConfig';
const emailRegex = /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [accessError, setAccessError] = useState('');
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [fetchError, setFetchError] = useState('');
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleLogin = () => {
    axiosInstance
      .post('/api/members/login', {
        email,
        password,
      })
      .then((response) => {
        // eslint-disable-next-line no-debugger
        const token = response.headers.authorization;

        if (token) {
          const decoded = jwt_decode(token);

          const user = {
            email: decoded.email,
            nickname: decoded.nickname,
            memberId: decoded.memberId,
          };

          sessionStorage.setItem('user', JSON.stringify(user)); // 세션스토리지에 user정보 저장
          sessionStorage.setItem('jwt', token); // sessionStorage에 토큰 저장

          dispatch(login(user));
          alert(`${user.nickname}님, 식사는 잡쉈어?`);
          navigate('api/boards');
        } else if (!token) {
          alert('이메일과 비밀번호를 확인하세요');
          navigate('/');
        } else {
          console.log(response.data);
          setAccessError('이메일 또는 비밀번호가 잘못되었습니다.');
        }
      })
      .catch((error) => {
        setFetchError('연결이 잘못되었습니다.');
        console.error('로그인 에러:', error);
      });
  };

  const validationEmail = (email) => {
    return emailRegex.test(email);
  };

  const validationPassword = (password) => {
    return passwordRegex.test(password);
  };

  const X = (e) => {
    console.log(1);
    setPassword(e.target.value);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!validationEmail(email)) {
      setEmailError('올바른 이메일 형식이 아닙니다.');
      return null;
    }
    if (!validationPassword(password)) {
      setPasswordError(
        '비밀번호는 영문, 숫자를 포함하여 8자리 이상이어야 합니다.'
      );
      return null;
    }
    handleLogin();
  };

  return (
    <>
      <BackGround>
        <BackYellow />
      </BackGround>
      <LogoContainer>
        <StyledLogo />
      </LogoContainer>
      <LoginContainer>
        <LoginTitle>Sign in now</LoginTitle>
        <LoginForm onSubmit={handleSubmit} noValidate>
          <Input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.currentTarget.value)}
          />
          <Error>{validationEmail(email) ? null : emailError}</Error>
          <Input
            type="password"
            placeholder="Password"
            value={password}
            onChange={X}
          />
          <Error>{validationPassword(password) ? null : passwordError}</Error>
          <Error>{accessError}</Error>
          <LoginButton
            type="submit"
            onClick={() => {
              //클릭을 했을 때 아이디와 비밀번호가 다르면 되게하는 기능을 구현하자.

              console.log('This button is made for Login');
            }}
          >
            Login
          </LoginButton>
          <Error>{fetchError}</Error>
          {/* <GoogleLoginButton
            type="button"
            onClick={() => {
              console.log('이자리가 맞니?');
            }}
          >
            <GoogleLogo />
            구글로 로그인
          </GoogleLoginButton> */}
        </LoginForm>
        <FooterText>아직 식구가 아니신가요?</FooterText>
        <StyledLink to="/signup">지금 바로 여기를 눌러 가입하세요.</StyledLink>
      </LoginContainer>
    </>
  );
};

export default Login;
