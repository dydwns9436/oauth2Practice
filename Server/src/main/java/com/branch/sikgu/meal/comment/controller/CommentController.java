package com.branch.sikgu.meal.comment.controller;

import com.branch.sikgu.meal.comment.dto.CommentDto;
import com.branch.sikgu.meal.comment.entity.Comment;
import com.branch.sikgu.meal.comment.mapper.CommentMapper;
import com.branch.sikgu.meal.comment.service.CommentService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.Positive;
import java.util.List;

@CrossOrigin(origins = "http://localhost:3000", allowedHeaders = "X-AUTH-TOKEN")
@RestController
@Validated
@RequestMapping("/api/boards")
@AllArgsConstructor
@Slf4j
public class CommentController {
    private final CommentService commentService;
    private final CommentMapper commentMapper;

    // 댓글 작성
    @PostMapping("/{board-id}/comments")
    public ResponseEntity postComment(@RequestHeader(name = "Authorization") String authentication,
                                      @PathVariable("board-id") @Positive long boardId,
                                      @Valid @RequestBody CommentDto.Post commentPostDto) {

        Comment comment = commentService.createComment(
                commentMapper.commentPostDto_to_Comment(commentPostDto), boardId, authentication);
        CommentDto.Response response = commentMapper.commentToCommentResponseDto(comment);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    //댓글 수정
    @PatchMapping("comments/{comment-id}")
    public ResponseEntity patchComment(@RequestHeader(name = "Authorization") String authentication,
//                                       @PathVariable("board-id") @Positive long boardId,
                                       @PathVariable("comment-id") @Positive long commentId,
                                       @Valid @RequestBody CommentDto.Patch commentPatchDto) {
        commentPatchDto.setCommentId(commentId);
        Comment comment = commentService.updateComment(
                commentMapper.commentPatchDto_to_Comment(commentPatchDto),
                authentication);
        CommentDto.Response response = commentMapper.commentToCommentResponseDto(comment);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    // 댓글 조회
    // 댓글 조회
    @GetMapping("{board-id}/comments")
    public ResponseEntity getComment(@PathVariable("board-id") @Positive long boardId){
        List<Comment> comments = commentService.findComments(boardId);

        List<CommentDto.Response> responses = commentMapper.comments_to_CommentResponseDto(comments);

        return new ResponseEntity<>(responses, HttpStatus.OK);
    }

    // 댓글 삭제
    @DeleteMapping("/comments/{comment-id}")
    public ResponseEntity deleteComment(@RequestHeader(name = "Authorization") String authentication,
                                        @PathVariable("comment-id") @Positive long commentId) {
        commentService.deleteComment(commentId, authentication);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
