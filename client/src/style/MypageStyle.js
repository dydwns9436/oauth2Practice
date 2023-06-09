import styled from 'styled-components';

export const BackGround = styled.div`
  position: absolute;
  z-index: -1;
  width: 100%;
  height: 100%;
  top: 0;
  left: 0;
`;

export const BackYellow = styled.div`
  background-image: linear-gradient(135deg, #ffd571, #ffac36);
  box-shadow: 0px 4px 40px rgba(0, 0, 0, 0.1);
  border-radius: 0 0 25px 25px;
  height: 272px;
  top: 0;
  left: 0;
`;

export const Mobile = styled.div`
  position: relative;
  font-family: 'Noto Sans KR', sans-serif;
  width: 400px;
  height: 100%;

  box-sizing: border-box;
  padding: 20px;
  overflow-y: auto;

  /* 스크롤바 */
  ::-webkit-scrollbar {
    display: none;
    width: 8px; /* 스크롤바 너비 */
  }

  /* 스크롤바 thumb */
  ::-webkit-scrollbar-thumb {
    background-color: rgba(0, 0, 0, 0.2); /* 스크롤바 색상 */
    border-radius: 4px; /* 스크롤바 모서리 반경 */
  }

  /* 스크롤바 track */
  ::-webkit-scrollbar-track {
    background-color: transparent; /* 스크롤바 트랙 색상 */
  }
`;

export const Profile = styled.div`
  display: flex;
  letter-spacing: -0.05em;

  > img {
    box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
    background-color: #cdeeff;
    box-sizing: border-box;
    border-radius: 10px;
    width: 125px;
    height: 200px;
    object-fit: cover;
  }

  > div:last-child {
    display: flex;
    flex-direction: column;
    justify-content: center;
    margin-left: 15px;
    flex: 1;

    > ul {
      list-style: none;
      margin: 0;
      padding: 0;
      color: white;

      > li:first-child {
        font-size: 18pt;
        font-weight: 700;

        > button {
          border: none;
          background-color: transparent;
          opacity: 0.8;

          > img {
            width: 20px;
            margin-left: 8px;
          }
        }
      }

      > li:nth-child(2) {
        font-size: 10pt;
        opacity: 0.9;
      }

      > li:last-child {
        display: flex;
        justify-content: space-between;

        > ul {
          display: flex;
          margin: 15px 0 0 0;
          padding: 0;

          font-size: 10pt;
          align-items: center;
          list-style: none;

          > li:first-child {
            width: 32px;
            height: 30px;
            margin-right: 10px;
            border-radius: 50px;
          }

          > li:last-child > div:first-child {
            font-weight: 700;
          }
        }
      }
    }
  }
`;

export const NewPosts = styled.div`
  display: flex;
  flex-direction: column;
  letter-spacing: -0.05em;

  h3 {
    margin: 20px 0 10px 0;
  }

  .post {
    display: flex;
    color: #393939;

    > div {
      background-color: white;
      box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.05);
      width: 175px;
      padding: 10px;
      border-radius: 10px;

      ul {
        list-style: none;
        margin: 0;
        padding: 0;

        li:nth-child(2) {
          text-align: right;
          font-size: 10pt;
          opacity: 0.5;
        }

        li:last-child {
          margin-top: 3px;
          text-align: right;
          font-weight: 600;
          color: #393939;
          overflow: hidden;
          white-space: nowrap;
          text-overflow: ellipsis;
        }
      }

      :first-child {
        margin-right: 10px;
      }
    }
  }
`;

export const History = styled.div`
  display: flex;
  flex-direction: column;
  letter-spacing: -0.05em;

  h3 {
    margin: 20px 0 10px 0;
  }

  .post {
    > div {
      display: flex;
      align-items: center;
      margin-bottom: 10px;
      color: #393939;

      width: 360px;
      padding: 10px;
      background-color: white;
      box-sizing: border-box;
      border-radius: 10px;
      box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.05);

      > img {
        background-color: #cdeeff;
        width: 50px;
        height: 50px;
        border-radius: 50px;
      }

      > div:nth-child(2) {
        flex: 1;

        ul {
          list-style: none;
          margin: 0 0 0 10px;
          padding: 0;

          li:first-child {
            font-weight: 700;
          }

          li:last-child {
            font-size: 10pt;
            opacity: 0.7;
          }
        }
      }

      > button:last-child {
        width: 30px;
        height: 30px;
        border-radius: 30px;
        background-color: #c9c9c9;
        color: white;
        border: none;

        display: flex;
        justify-content: center;
        align-items: center;
        font-size: 14pt;
        font-weight: 700;
        cursor: pointer;

        transition: background-color 0.3s ease;

        :hover {
          background-color: #ffca61 !important;
        }
      }
    }
  }
`;

export const PostIcon = styled.div`
  background-image: ${(props) =>
    props.isType === '식구'
      ? `url("${props.imageA}")`
      : `url("${props.imageB}")`};
  width: 35px;
  height: 30px;
  background-repeat: no-repeat;
`;

export const NotFound = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  height: 80px;
`;
