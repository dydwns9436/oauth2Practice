import styled, { keyframes } from 'styled-components';

const slideIn = keyframes`
  0% {
    transform: translateY(100%);
  }
  100% {
    transform: translateY(0%);
  }
`;

export const ModalWrap = styled.div`
  position: fixed;
  bottom: 0;
  left: 0;
  width: 100%;
  height: 100%;
  display: flex;
  align-items: flex-end;
  justify-content: center;
  background-color: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(10px);
  z-index: 999;
  visibility: ${({ isOpen }) => (isOpen ? 'visible' : 'hidden')};
  opacity: ${({ isOpen }) => (isOpen ? '1' : '0')};
`;

export const ModalContent = styled.form`
  position: relative;
  bottom: ${({ isOpen }) => (isOpen ? '0' : '-100%')};
  left: 0;
  background-color: #fffaed;
  font-size: 15px;
  border-top-right-radius: 40px;
  border-top-left-radius: 40px;
  padding: 20px;
  width: 100%;
  height: 90%;
  max-width: 500px;
  display: flex;
  flex-direction: column;
  align-items: start;
  animation: ${slideIn} 0.5s;
  transition: bottom 0.5s;
  z-index: 9999;
`;

/////////////////////////////////////

export const ModalQurry = styled.div`
  padding: 10px;
  font-size: 18px;
  font-size: 17px;
`;

export const ModalInput = styled.input`
  width: 340px;
  margin-left: 10px;
  padding: 10px;
  font-size: 14px;
  border-radius: 5%;
  border: none;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
  &:focus {
    outline: none;
  }
`;

export const ModalCount = styled.div`
  padding: 10px;
  width: 340px;
  margin-left: 10px;
  border-radius: 5%;
  height: 38px;
  border: 1px solid black;
  background-color: white;
  display: flex;
  justify-content: space-between;
  border: none;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
`;

export const ModalCountbutton = styled.button`
  border-radius: 50%;
  background-color: #9b9b9b;
  color: white;
  width: 18px;
  height: 18px;
  border: none;
  display: flex;
  justify-content: center;
  align-items: center;
  cursor: pointer;
  text-align: center;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
  &:hover {
    background-color: #696969;
  }
`;

export const ModalPlusbutton = styled.button`
  border-radius: 50%;
  background-color: #ffb44a;
  color: white;
  width: 18px;
  height: 18px;
  border: none;
  cursor: pointer;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
  &:hover {
    background-image: radial-gradient(#ffb44a, #ffca28);
  }
`;

export const ModalWhenInput = styled.input`
  padding: 10px;
  width: 325px;
  font-size: 14px;
  border-radius: 5%;
`;

export const ModalWhoButtonWrap = styled.div`
  padding: 10px;
  margin-left: 10px;
  border-radius: 5%;
  width: 340px;
  background-color: white;
  display: flex;
  justify-content: space-between;
`;

export const ModalWhobutton = styled.button`
  border-radius: 50%;
  background-color: #ffb44a;
  color: white;
  width: 18px;
  height: 18px;
  border: none;
  cursor: pointer;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
  &:hover {
    background-image: radial-gradient(#ffb44a, #ffca28);
  }
`;

export const ModalText = styled.textarea`
  padding: 10px;
  margin-left: 10px;
  width: 340px;
  height: 132px;
  font-size: 12px;
  border: none;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
  border-radius: 10px;
  &:focus {
    outline: none;
  }
`;

export const ModalTag = styled.input`
  margin-top: 20px;
  padding: 10px;
  font-size: 12px;
  width: 325px;
  &:focus {
    outline: none;
  }
`;

export const ModalButtonWrap = styled.div`
  padding: 10px;
  width: 340px;
  display: flex;
  justify-content: space-between;
`;

export const ModalButton = styled.button`
  width: 148px;
  height: 48px;
  border-radius: 40px;
  color: white;
  border: none;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
  background-color: #ffb44a;
  transition: background-color 0.3s ease;
  &:hover {
    background-image: radial-gradient(#ffb44a, #ffca28);
  }
`;
export const CancelButton = styled.button`
  width: 148px;
  height: 48px;
  border-radius: 40px;
  color: white;
  border: none;
  box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.1);
  background-color: #9b9b9b;
  transition: background-color 0.3s ease;

  &:hover {
    background-color: #696969;
  }
`;
