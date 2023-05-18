import { HeaderBackWrap, HeaderWrap, LogoWrap } from '../style/MapStyle';
import { NavLink } from 'react-router-dom';

const MapHeader = () => {
  return (
    <HeaderBackWrap>
      <HeaderWrap>
        <NavLink to="/boards">
          <LogoWrap src="/Logo/Logo4.png" />
        </NavLink>
      </HeaderWrap>
    </HeaderBackWrap>
  );
};

export default MapHeader;