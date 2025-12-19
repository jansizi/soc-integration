package models

import "math"

type Pagination struct {
	CurrentPage int   `json:"current_page"`
	PageSize    int   `json:"page_size"`
	TotalItems  int64 `json:"total_items"`
}

func (p *Pagination) GetOffset() int {
	return (p.CurrentPage - 1) * p.PageSize
}

func (p *Pagination) TotalPages() int {
	if p.PageSize == 0 {
		return 0
	}
	return int(math.Ceil(float64(p.TotalItems) / float64(p.PageSize)))
}

func (p *Pagination) HasPrev() bool {
	return p.CurrentPage > 1
}

func (p *Pagination) HasNext() bool {
	return p.CurrentPage < p.TotalPages()
}

func (p *Pagination) PrevPage() int {
	if p.HasPrev() {
		return p.CurrentPage - 1
	}
	return 1
}

func (p *Pagination) NextPage() int {
	if p.HasNext() {
		return p.CurrentPage + 1
	}
	return p.TotalPages()
}

func (p *Pagination) Pages() []int {
	total := p.TotalPages()
	var pages []int
	for i := 1; i <= total; i++ {
		pages = append(pages, i)
	}
	return pages
}
