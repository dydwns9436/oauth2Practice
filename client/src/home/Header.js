import {
  HeaderBackWrap,
  HeaderWrap,
  LogoWrap,
  SearchWrap,
  LogoutButton,
} from './HomeStyle';
import { AiOutlineSearch } from 'react-icons/ai';
import { useState } from 'react';
import styled from 'styled-components';
import { useDispatch } from 'react-redux';
import { logout } from '../store/userSlice';
import { setSearchTerm } from '../store/boardSlice';
import { useNavigate } from 'react-router-dom';

const Header = () => {
  const [onSearch, setOnSerach] = useState(false);

  const dispatch = useDispatch();
  const navigate = useNavigate();

  const handleLogout = () => {
    sessionStorage.removeItem('user');
    sessionStorage.removeItem('jwt');
    alert('로그아웃 되었습니다.');
    dispatch(logout());
    navigate('/');
  };

  const SearchHandler = () => {
    setOnSerach(!onSearch);
  };

  const onSearchTermChange = (e) => {
    dispatch(setSearchTerm(e.target.value));
  };

  const SearchSpan = styled.input`
    display: ${() => (onSearch ? 'block' : 'none')};
    margin: 20px;
    padding: 0px;
    height: 10%;
    width: 85%;
    border: 1px solid black;
    border-radius: 10px;
  `;

  //   const SearchIcon = styled(AiOutlineSearch)`
  //     position: absolute;
  //     top: 50%;
  //     right: 10px;
  //     transform: translateY(-50%);
  //   `;

  return (
    <>
      <HeaderBackWrap>
        <LogoutButton onClick={handleLogout}>로그아웃</LogoutButton>
        {onSearch ? (
          <>
            <SearchSpan
              visible={onSearch}
              placeholder="무슨 기준으로 검색할까요?"
              onChange={onSearchTermChange}
            ></SearchSpan>
            <SearchWrap>
              <AiOutlineSearch
                className="icon"
                onClick={SearchHandler}
                color="white"
              ></AiOutlineSearch>
            </SearchWrap>
          </>
        ) : (
          <>
            <HeaderWrap>
              <LogoWrap src="/Logo/Logo4.png" />
            </HeaderWrap>
            <SearchWrap>
              <AiOutlineSearch
                className="icon"
                onClick={SearchHandler}
                color="white"
              ></AiOutlineSearch>
            </SearchWrap>
          </>
        )}
      </HeaderBackWrap>
    </>
  );
};

export default Header;
